use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use cros_codecs::{
    BlockingMode, Fourcc, FrameLayout, PlaneLayout, Resolution,
    backend::vaapi::encoder::VaapiBackend,
    codec::h264::parser::{Level, Profile as VaapiProfile},
    encoder::{
        FrameMetadata, PredictionStructure, RateControl, Tunings, VideoEncoder,
        h264::EncoderConfig as VaapiEncoderConfig,
        stateless::h264::StatelessEncoder as VaapiStatelessEncoder,
    },
    libva::{
        Display, Surface, VAEntrypoint::VAEntrypointEncSliceLP,
        VAProfile::VAProfileH264ConstrainedBaseline,
    },
    video_frame::{
        VideoFrame,
        gbm_video_frame::{GbmDevice, GbmExternalBufferDescriptor, GbmUsage, GbmVideoFrame},
    },
};
use glacialcast_dash::AvcConfig;
use image::{ImageBuffer, Rgb};
use openh264::{
    OpenH264API,
    encoder::{
        BitRate, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, Profile,
        RateControlMode, UsageType,
    },
    formats::{RgbSliceU8, YUVBuffer},
};
use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};
use tracing::{info, warn};

const OPENH264_ABI_MAJOR: &str = "8";
const OPENH264_VERSION: &str = "2.6.0";
const VAAPI_CODED_ALIGNMENT: u32 = 16;
const VAAPI_PREDICTION_LIMIT: u16 = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DashEncoderMode {
    Auto,
    Vaapi,
    Openh264,
}

pub struct DashH264Encoder {
    backend: EncoderBackend,
    fallback: Option<SoftwareEncoderSettings>,
    encoded_any: bool,
}

enum EncoderBackend {
    Vaapi(Box<VaapiH264Encoder>),
    Openh264(Box<SoftwareH264Encoder>),
}

#[derive(Clone)]
struct SoftwareEncoderSettings {
    library: Option<PathBuf>,
    width: u32,
    height: u32,
    fps: f64,
    bitrate: u32,
    keyframe_interval: u16,
}

type CrosVaapiEncoder = VaapiStatelessEncoder<
    GbmVideoFrame,
    VaapiBackend<GbmExternalBufferDescriptor, Surface<GbmExternalBufferDescriptor>>,
>;

pub struct SoftwareH264Encoder {
    encoder: Encoder,
    width: u16,
    height: u16,
    parameter_sets: Option<AvcConfig>,
}

pub struct EncodedH264Frame {
    pub annex_b: Vec<u8>,
    pub keyframe: bool,
    pub config: Option<AvcConfig>,
}

struct VaapiH264Encoder {
    display: Rc<Display>,
    device: Arc<GbmDevice>,
    encoder: CrosVaapiEncoder,
    width: u16,
    height: u16,
    coded_size: Resolution,
    fps: u32,
    bitrate: u32,
    frames_encoded: u64,
    parameter_sets: Option<AvcConfig>,
    low_power: bool,
}

impl DashH264Encoder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: DashEncoderMode,
        vaapi_device: &Path,
        openh264_library: Option<&Path>,
        width: u32,
        height: u32,
        fps: f64,
        bitrate: u32,
        keyframe_interval: u16,
    ) -> Result<Self> {
        validate_dimensions(width, height, "H.264")?;
        let software = SoftwareEncoderSettings {
            library: openh264_library.map(Path::to_path_buf),
            width,
            height,
            fps,
            bitrate,
            keyframe_interval,
        };
        match mode {
            DashEncoderMode::Vaapi => {
                let encoder = VaapiH264Encoder::new(vaapi_device, width, height, fps, bitrate)
                    .context("initializing required VA-API H.264 encoder")?;
                info!(
                    device = %vaapi_device.display(),
                    low_power = encoder.low_power,
                    "using VA-API H.264 encoder"
                );
                Ok(Self {
                    backend: EncoderBackend::Vaapi(Box::new(encoder)),
                    fallback: None,
                    encoded_any: false,
                })
            }
            DashEncoderMode::Openh264 => {
                let encoder = software.build()?;
                info!("using OpenH264 software encoder");
                Ok(Self {
                    backend: EncoderBackend::Openh264(Box::new(encoder)),
                    fallback: None,
                    encoded_any: false,
                })
            }
            DashEncoderMode::Auto => {
                match VaapiH264Encoder::new(vaapi_device, width, height, fps, bitrate) {
                    Ok(encoder) => {
                        info!(
                            device = %vaapi_device.display(),
                            low_power = encoder.low_power,
                            "using VA-API H.264 encoder"
                        );
                        Ok(Self {
                            backend: EncoderBackend::Vaapi(Box::new(encoder)),
                            fallback: Some(software),
                            encoded_any: false,
                        })
                    }
                    Err(err) => {
                        warn!(
                            device = %vaapi_device.display(),
                            error = %format!("{err:#}"),
                            "VA-API unavailable; falling back to OpenH264"
                        );
                        let encoder = software.build()?;
                        Ok(Self {
                            backend: EncoderBackend::Openh264(Box::new(encoder)),
                            fallback: None,
                            encoded_any: false,
                        })
                    }
                }
            }
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            EncoderBackend::Vaapi(_) => "vaapi",
            EncoderBackend::Openh264(_) => "openh264",
        }
    }

    pub fn encode(
        &mut self,
        image: &ImageBuffer<Rgb<u8>, Vec<u8>>,
        force_keyframe: bool,
    ) -> Result<EncodedH264Frame> {
        let result = match &mut self.backend {
            EncoderBackend::Vaapi(encoder) => encoder.encode(image, force_keyframe),
            EncoderBackend::Openh264(encoder) => encoder.encode(image, force_keyframe),
        };
        match result {
            Ok(frame) => {
                self.encoded_any = true;
                Ok(frame)
            }
            Err(vaapi_error)
                if !self.encoded_any
                    && matches!(self.backend, EncoderBackend::Vaapi(_))
                    && self.fallback.is_some() =>
            {
                warn!(
                    error = %format!("{vaapi_error:#}"),
                    "VA-API failed on the first frame; falling back to OpenH264"
                );
                let mut software = self
                    .fallback
                    .take()
                    .expect("fallback presence checked")
                    .build()?;
                let frame = software.encode(image, force_keyframe)?;
                self.backend = EncoderBackend::Openh264(Box::new(software));
                self.encoded_any = true;
                Ok(frame)
            }
            Err(err) => Err(err),
        }
    }
}

impl SoftwareEncoderSettings {
    fn build(&self) -> Result<SoftwareH264Encoder> {
        SoftwareH264Encoder::new(
            self.library.as_deref(),
            self.width,
            self.height,
            self.fps,
            self.bitrate,
            self.keyframe_interval,
        )
    }
}

impl SoftwareH264Encoder {
    pub fn new(
        library: Option<&Path>,
        width: u32,
        height: u32,
        fps: f64,
        bitrate: u32,
        keyframe_interval: u16,
    ) -> Result<Self> {
        validate_dimensions(width, height, "OpenH264")?;
        let library = resolve_openh264_library(library)?;
        // SAFETY: openh264-sys2 0.9.7 targets OpenH264 2.6.0. The path validator
        // only accepts that release or its ABI-major-8 soname before loading it.
        let api = unsafe { OpenH264API::from_blob_path_unchecked(&library) }
            .with_context(|| format!("loading OpenH264 from {}", library.display()))?;
        let config = EncoderConfig::new()
            .bitrate(BitRate::from_bps(bitrate))
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            .usage_type(UsageType::ScreenContentRealTime)
            .profile(Profile::Baseline)
            .rate_control_mode(RateControlMode::Bufferbased)
            .intra_frame_period(IntraFramePeriod::from_num_frames(u32::from(
                keyframe_interval,
            )))
            .skip_frames(false)
            .scene_change_detect(true)
            .adaptive_quantization(false)
            .background_detection(false);
        let encoder = Encoder::with_api_config(api, config).context("initializing OpenH264")?;
        Ok(Self {
            encoder,
            width: width as u16,
            height: height as u16,
            parameter_sets: None,
        })
    }

    pub fn encode(
        &mut self,
        image: &ImageBuffer<Rgb<u8>, Vec<u8>>,
        force_keyframe: bool,
    ) -> Result<EncodedH264Frame> {
        if image.width() != u32::from(self.width) || image.height() != u32::from(self.height) {
            bail!(
                "encoder dimensions changed from {}x{} to {}x{}",
                self.width,
                self.height,
                image.width(),
                image.height()
            );
        }
        if force_keyframe {
            self.encoder.force_intra_frame();
        }
        let rgb = RgbSliceU8::new(
            image.as_raw(),
            (usize::from(self.width), usize::from(self.height)),
        );
        let yuv = YUVBuffer::from_rgb_source(rgb);
        let bitstream = self.encoder.encode(&yuv).context("encoding H.264 frame")?;
        let frame_type = bitstream.frame_type();
        let annex_b = bitstream.to_vec();
        if annex_b.is_empty() || matches!(frame_type, FrameType::Invalid | FrameType::Skip) {
            bail!("OpenH264 did not emit an encodable frame");
        }
        inspect_encoded_frame(
            annex_b,
            self.width,
            self.height,
            &mut self.parameter_sets,
            frame_type == FrameType::IDR,
            "OpenH264",
        )
    }
}

impl VaapiH264Encoder {
    fn new(device_path: &Path, width: u32, height: u32, fps: f64, bitrate: u32) -> Result<Self> {
        validate_dimensions(width, height, "VA-API")?;
        let display = Display::open_drm_display(device_path)
            .with_context(|| format!("opening VA-API device {}", device_path.display()))?;
        let device = GbmDevice::open(device_path)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("opening GBM device {}", device_path.display()))?;
        let entrypoints = display
            .query_config_entrypoints(VAProfileH264ConstrainedBaseline)
            .context("querying VA-API constrained-baseline entrypoints")?;
        let low_power = entrypoints.contains(&VAEntrypointEncSliceLP);
        let coded_size = Resolution {
            width: align_up(width, VAAPI_CODED_ALIGNMENT),
            height: align_up(height, VAAPI_CODED_ALIGNMENT),
        };
        let fps = fps.round().clamp(1.0, f64::from(u32::MAX)) as u32;
        let encoder =
            build_vaapi_encoder(&display, width, height, coded_size, fps, bitrate, low_power)?;
        Ok(Self {
            display,
            device,
            encoder,
            width: width as u16,
            height: height as u16,
            coded_size,
            fps,
            bitrate,
            frames_encoded: 0,
            parameter_sets: None,
            low_power,
        })
    }

    fn encode(
        &mut self,
        image: &ImageBuffer<Rgb<u8>, Vec<u8>>,
        force_keyframe: bool,
    ) -> Result<EncodedH264Frame> {
        if image.width() != u32::from(self.width) || image.height() != u32::from(self.height) {
            bail!(
                "encoder dimensions changed from {}x{} to {}x{}",
                self.width,
                self.height,
                image.width(),
                image.height()
            );
        }
        if force_keyframe && self.frames_encoded > 0 {
            self.encoder = build_vaapi_encoder(
                &self.display,
                u32::from(self.width),
                u32::from(self.height),
                self.coded_size,
                self.fps,
                self.bitrate,
                self.low_power,
            )
            .context("restarting VA-API encoder for a DASH random-access segment")?;
            self.frames_encoded = 0;
        }

        let mut frame = Arc::clone(&self.device)
            .new_frame(
                Fourcc::from(b"NV12"),
                Resolution {
                    width: u32::from(self.width),
                    height: u32::from(self.height),
                },
                self.coded_size,
                GbmUsage::Encode,
            )
            .map_err(anyhow::Error::msg)
            .context("allocating VA-API NV12 input frame")?;
        let pitches = frame.get_plane_pitch();
        {
            let mapping = frame
                .map_mut()
                .map_err(anyhow::Error::msg)
                .context("mapping VA-API NV12 input frame")?;
            let planes = mapping.get();
            if planes.len() != 2 || pitches.len() != 2 {
                bail!("VA-API NV12 input did not expose two planes");
            }
            let mut y_plane = planes[0].borrow_mut();
            let mut uv_plane = planes[1].borrow_mut();
            rgb_to_nv12(image, &mut y_plane, pitches[0], &mut uv_plane, pitches[1])?;
        }

        let timestamp = self.frames_encoded;
        self.encoder
            .encode(
                FrameMetadata {
                    timestamp,
                    layout: FrameLayout {
                        format: (Fourcc::from(b"NV12"), 0),
                        size: Resolution {
                            width: u32::from(self.width),
                            height: u32::from(self.height),
                        },
                        planes: vec![
                            PlaneLayout {
                                buffer_index: 0,
                                offset: 0,
                                stride: pitches[0],
                            },
                            PlaneLayout {
                                buffer_index: 0,
                                offset: pitches[0] * usize::from(self.height),
                                stride: pitches[1],
                            },
                        ],
                    },
                    force_keyframe: false,
                },
                frame,
            )
            .map_err(|err| anyhow!("submitting frame to VA-API H.264 encoder: {err}"))?;
        let coded = self
            .encoder
            .poll()
            .map_err(|err| anyhow!("polling VA-API H.264 encoder: {err}"))?
            .context("VA-API accepted a frame without producing output")?;
        self.frames_encoded = self.frames_encoded.saturating_add(1);
        inspect_encoded_frame(
            coded.bitstream,
            self.width,
            self.height,
            &mut self.parameter_sets,
            false,
            "VA-API",
        )
    }
}

fn build_vaapi_encoder(
    display: &Rc<Display>,
    width: u32,
    height: u32,
    coded_size: Resolution,
    fps: u32,
    bitrate: u32,
    low_power: bool,
) -> Result<CrosVaapiEncoder> {
    VaapiStatelessEncoder::new_vaapi(
        Rc::clone(display),
        VaapiEncoderConfig {
            resolution: Resolution { width, height },
            profile: VaapiProfile::Baseline,
            level: Level::L4,
            pred_structure: PredictionStructure::LowDelay {
                limit: VAAPI_PREDICTION_LIMIT,
            },
            initial_tunings: Tunings {
                rate_control: RateControl::ConstantBitrate(u64::from(bitrate)),
                framerate: fps,
                ..Default::default()
            },
        },
        Fourcc::from(b"NV12"),
        coded_size,
        low_power,
        BlockingMode::Blocking,
    )
    .map_err(|err| anyhow!("creating VA-API constrained-baseline encoder: {err}"))
}

fn inspect_encoded_frame(
    annex_b: Vec<u8>,
    width: u16,
    height: u16,
    parameter_sets: &mut Option<AvcConfig>,
    keyframe_hint: bool,
    backend: &str,
) -> Result<EncodedH264Frame> {
    if annex_b.is_empty() {
        bail!("{backend} did not emit an encodable frame");
    }
    let nals = annex_b_nals(&annex_b);
    let keyframe = keyframe_hint || nals.iter().any(|nal| nal[0] & 0x1f == 5);
    let sps = nals
        .iter()
        .find(|nal| nal[0] & 0x1f == 7)
        .map(|nal| nal.to_vec());
    let pps = nals
        .iter()
        .find(|nal| nal[0] & 0x1f == 8)
        .map(|nal| nal.to_vec());
    let config = match (sps, pps) {
        (Some(sps), Some(pps)) => {
            let config = AvcConfig {
                width,
                height,
                sps,
                pps,
            };
            *parameter_sets = Some(config.clone());
            Some(config)
        }
        _ => None,
    };
    if parameter_sets.is_none() {
        bail!("{backend} did not emit SPS/PPS before its first video sample");
    }
    Ok(EncodedH264Frame {
        annex_b,
        keyframe,
        config,
    })
}

fn validate_dimensions(width: u32, height: u32, backend: &str) -> Result<()> {
    if width == 0
        || height == 0
        || !width.is_multiple_of(2)
        || !height.is_multiple_of(2)
        || width > u16::MAX.into()
        || height > u16::MAX.into()
    {
        bail!("{backend} requires non-zero, even dimensions that fit in 16 bits");
    }
    Ok(())
}

fn align_up(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}

fn rgb_to_nv12(
    image: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    y_plane: &mut [u8],
    y_stride: usize,
    uv_plane: &mut [u8],
    uv_stride: usize,
) -> Result<()> {
    let width = image.width() as usize;
    let height = image.height() as usize;
    if y_plane.len() < y_stride.saturating_mul(height)
        || uv_plane.len() < uv_stride.saturating_mul(height / 2)
        || y_stride < width
        || uv_stride < width
    {
        bail!("VA-API NV12 plane layout is smaller than the captured frame");
    }
    let rgb = image.as_raw();
    for y in 0..height {
        for x in 0..width {
            let offset = (y * width + x) * 3;
            let [r, g, b] = [rgb[offset], rgb[offset + 1], rgb[offset + 2]];
            y_plane[y * y_stride + x] = rgb_luma(r, g, b);
        }
    }
    for y in (0..height).step_by(2) {
        for x in (0..width).step_by(2) {
            let mut r = 0u32;
            let mut g = 0u32;
            let mut b = 0u32;
            for row in 0..2 {
                for column in 0..2 {
                    let offset = ((y + row) * width + x + column) * 3;
                    r += u32::from(rgb[offset]);
                    g += u32::from(rgb[offset + 1]);
                    b += u32::from(rgb[offset + 2]);
                }
            }
            let (u, v) = rgb_chroma((r / 4) as u8, (g / 4) as u8, (b / 4) as u8);
            let offset = (y / 2) * uv_stride + x;
            uv_plane[offset] = u;
            uv_plane[offset + 1] = v;
        }
    }
    Ok(())
}

fn rgb_luma(r: u8, g: u8, b: u8) -> u8 {
    let value = 47 * i32::from(r) + 157 * i32::from(g) + 16 * i32::from(b);
    ((value + 128) >> 8).saturating_add(16).clamp(16, 235) as u8
}

fn rgb_chroma(r: u8, g: u8, b: u8) -> (u8, u8) {
    let r = i32::from(r);
    let g = i32::from(g);
    let b = i32::from(b);
    let u = ((-26 * r - 87 * g + 113 * b + 128) >> 8) + 128;
    let v = ((112 * r - 102 * g - 10 * b + 128) >> 8) + 128;
    (u.clamp(16, 240) as u8, v.clamp(16, 240) as u8)
}

pub fn resolve_openh264_library(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        validate_openh264_library(path)?;
        return Ok(path.to_path_buf());
    }
    const CANDIDATES: &[&str] = &[
        "/lib64/libopenh264.so.8",
        "/usr/lib64/libopenh264.so.8",
        "/lib/x86_64-linux-gnu/libopenh264.so.8",
        "/usr/lib/x86_64-linux-gnu/libopenh264.so.8",
    ];
    CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
        .context(
            "OpenH264 2.6 (libopenh264.so.8) was not found; install it or pass --openh264-library",
        )
}

fn validate_openh264_library(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!(
            "OpenH264 library does not exist or is not a file: {}",
            path.display()
        );
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("OpenH264 library path has no UTF-8 file name")?;
    let accepted_soname = format!("libopenh264.so.{OPENH264_ABI_MAJOR}");
    let accepted_release = format!("libopenh264.so.{OPENH264_VERSION}");
    if name != accepted_soname && name != accepted_release {
        bail!(
            "unsupported OpenH264 library {name}; expected {accepted_soname} or {accepted_release}"
        );
    }
    Ok(())
}

fn annex_b_nals(access_unit: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut cursor = 0usize;
    while cursor + 3 <= access_unit.len() {
        if access_unit[cursor..].starts_with(&[0, 0, 1]) {
            starts.push((cursor, 3));
            cursor += 3;
        } else if access_unit[cursor..].starts_with(&[0, 0, 0, 1]) {
            starts.push((cursor, 4));
            cursor += 4;
        } else {
            cursor += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .filter_map(|(index, (start, prefix))| {
            let begin = start + prefix;
            let end = starts
                .get(index + 1)
                .map(|(next, _)| *next)
                .unwrap_or(access_unit.len());
            (begin < end).then_some(&access_unit[begin..end])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_mixed_annex_b_start_codes() {
        let bytes = [
            0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 4,
        ];
        let nals = annex_b_nals(&bytes);
        assert_eq!(
            nals,
            vec![&[0x67, 1, 2][..], &[0x68, 3][..], &[0x65, 4][..]]
        );
    }

    #[test]
    fn rejects_an_unversioned_explicit_library() {
        let err = validate_openh264_library(Path::new("/lib64/libopenh264.so")).unwrap_err();
        assert!(
            err.to_string().contains("does not exist") || err.to_string().contains("unsupported")
        );
    }

    #[test]
    fn converts_rgb_to_padded_nv12() {
        let image = ImageBuffer::from_fn(2, 2, |x, _| {
            if x == 0 {
                Rgb([0, 0, 0])
            } else {
                Rgb([255, 255, 255])
            }
        });
        let mut y = vec![0xaa; 8];
        let mut uv = vec![0xbb; 4];
        rgb_to_nv12(&image, &mut y, 4, &mut uv, 4).unwrap();
        assert_eq!(&y[..4], &[16, 235, 0xaa, 0xaa]);
        assert_eq!(&y[4..], &[16, 235, 0xaa, 0xaa]);
        assert_eq!(&uv[..2], &[128, 128]);
        assert_eq!(&uv[2..], &[0xbb, 0xbb]);
    }

    #[test]
    fn validates_h264_dimensions() {
        assert!(validate_dimensions(1280, 720, "test").is_ok());
        assert!(validate_dimensions(1279, 720, "test").is_err());
        assert!(validate_dimensions(1280, 0, "test").is_err());
        assert_eq!(align_up(721, VAAPI_CODED_ALIGNMENT), 736);
    }
}
