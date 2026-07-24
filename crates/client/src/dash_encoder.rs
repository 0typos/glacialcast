use anyhow::{Context, Result, bail};
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
use std::path::{Path, PathBuf};

const OPENH264_ABI_MAJOR: &str = "8";
const OPENH264_VERSION: &str = "2.6.0";

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

impl SoftwareH264Encoder {
    pub fn new(
        library: Option<&Path>,
        width: u32,
        height: u32,
        fps: f64,
        bitrate: u32,
        keyframe_interval: u16,
    ) -> Result<Self> {
        if width == 0
            || height == 0
            || !width.is_multiple_of(2)
            || !height.is_multiple_of(2)
            || width > u16::MAX.into()
            || height > u16::MAX.into()
        {
            bail!("OpenH264 requires non-zero, even dimensions that fit in 16 bits");
        }
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
        let nals = annex_b_nals(&annex_b);
        let keyframe = frame_type == FrameType::IDR || nals.iter().any(|nal| nal[0] & 0x1f == 5);

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
                    width: self.width,
                    height: self.height,
                    sps,
                    pps,
                };
                self.parameter_sets = Some(config.clone());
                Some(config)
            }
            _ => None,
        };
        if self.parameter_sets.is_none() {
            bail!("OpenH264 did not emit SPS/PPS before its first video sample");
        }
        if annex_b.is_empty() || matches!(frame_type, FrameType::Invalid | FrameType::Skip) {
            bail!("OpenH264 did not emit an encodable frame");
        }

        Ok(EncodedH264Frame {
            annex_b,
            keyframe,
            config,
        })
    }
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
}
