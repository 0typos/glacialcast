#![allow(unsafe_op_in_unsafe_fn)]

use anyhow::{Context, Result, bail};
use ffmpeg_sys_next as ffi;
use std::{
    env,
    ffi::{CStr, CString},
    mem,
    os::fd::RawFd,
    path::Path,
    ptr, slice,
};
use tracing::{info, warn};

const AVERROR_EAGAIN: i32 = -libc::EAGAIN;
const AV_NOPTS_VALUE: i64 = i64::MIN;
const FILTER_TIME_BASE_DEN: i32 = 1000;

pub struct DmaBufInputFrame {
    pub fd: RawFd,
    pub size: usize,
    pub offset: usize,
    pub stride: i32,
    pub drm_format: u32,
    pub modifier: u64,
    pub width: u32,
    pub height: u32,
    pub captured_at_ms: i64,
}

pub struct RgbInputFrame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub captured_at_ms: i64,
}

pub struct EncodedH264Packet {
    pub payload: Vec<u8>,
    pub keyframe: bool,
    pub captured_at_ms: i64,
    pub pts_ms: i64,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub source_width: u32,
    pub source_height: u32,
}

pub fn ensure_h264_vaapi_available() -> Result<()> {
    let codec_name = CString::new("h264_vaapi")?;
    let codec = unsafe { ffi::avcodec_find_encoder_by_name(codec_name.as_ptr()) };
    if codec.is_null() {
        bail!("FFmpeg libavcodec does not expose the h264_vaapi encoder");
    }
    Ok(())
}

pub fn ensure_software_h264_available() -> Result<()> {
    find_software_h264_encoders().next().map(|_| ()).context(
        "FFmpeg libavcodec does not expose libx264, libopenh264, or a software H.264 encoder",
    )
}

pub fn software_h264_encoder_available() -> bool {
    find_software_h264_encoders().next().is_some()
}

pub struct SoftwareH264Encoder {
    target_width: u32,
    target_height: u32,
    fps: f64,
    started_at_ms: i64,
    frame_index: i64,
    codec_ctx: *mut ffi::AVCodecContext,
    packet: *mut ffi::AVPacket,
    sws_ctx: *mut ffi::SwsContext,
    frame: AvFrame,
    force_keyframe: bool,
}

unsafe impl Send for SoftwareH264Encoder {}

impl SoftwareH264Encoder {
    pub fn new(
        target_width: u32,
        target_height: u32,
        fps: f64,
        started_at_ms: i64,
    ) -> Result<Self> {
        let target_width = target_width.max(1);
        let target_height = target_height.max(1);
        let fps = fps.clamp(0.5, 15.0);
        let mut errors = Vec::new();
        let mut candidates = 0;
        for (codec_name, codec) in find_software_h264_encoders() {
            candidates += 1;
            match Self::try_new_with_encoder(
                target_width,
                target_height,
                fps,
                started_at_ms,
                &codec_name,
                codec,
            ) {
                Ok(encoder) => return Ok(encoder),
                Err(err) => {
                    warn!(encoder = %codec_name, ?err, "FFmpeg H.264 encoder candidate failed");
                    errors.push(format!("{codec_name}: {err:#}"));
                }
            }
        }
        if candidates == 0 {
            bail!(
                "FFmpeg libavcodec does not expose h264_nvenc, libx264, libopenh264, or a software H.264 encoder"
            );
        }
        bail!(
            "all FFmpeg H.264 encoder candidates failed to initialize: {}",
            errors.join("; ")
        )
    }

    fn try_new_with_encoder(
        target_width: u32,
        target_height: u32,
        fps: f64,
        started_at_ms: i64,
        codec_name: &str,
        codec: *const ffi::AVCodec,
    ) -> Result<Self> {
        let ctx = unsafe { ffi::avcodec_alloc_context3(codec) };
        if ctx.is_null() {
            bail!("allocating software H.264 codec context failed");
        }
        let packet = unsafe { ffi::av_packet_alloc() };
        if packet.is_null() {
            unsafe {
                let mut ctx_to_free = ctx;
                ffi::avcodec_free_context(&mut ctx_to_free);
            }
            bail!("allocating H.264 packet failed");
        }
        let frame = match AvFrame::new() {
            Ok(frame) => frame,
            Err(err) => {
                unsafe {
                    let mut packet_to_free = packet;
                    let mut ctx_to_free = ctx;
                    ffi::av_packet_free(&mut packet_to_free);
                    ffi::avcodec_free_context(&mut ctx_to_free);
                }
                return Err(err);
            }
        };
        let (fps_num, fps_den) = fps_rational(fps);
        let open_result = unsafe {
            (*ctx).width = target_width as i32;
            (*ctx).height = target_height as i32;
            (*ctx).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
            (*ctx).framerate = ffi::AVRational {
                num: fps_num,
                den: fps_den,
            };
            (*ctx).pix_fmt = ffi::AVPixelFormat::AV_PIX_FMT_YUV420P;
            (*ctx).max_b_frames = 0;
            (*ctx).gop_size = fps_num.div_euclid(fps_den).max(1);
            (*ctx).keyint_min = (*ctx).gop_size;
            (*ctx).bit_rate = recommended_bitrate(target_width, target_height, fps);
            (*ctx).rc_max_rate = (*ctx).bit_rate;
            (*ctx).rc_buffer_size = ((*ctx).bit_rate / 6).clamp(1, i32::MAX as i64) as i32;
            (*ctx).thread_count = 1;
            let key_interval = (*ctx).gop_size.max(1);

            (*frame.ptr).format = ffi::AVPixelFormat::AV_PIX_FMT_YUV420P as i32;
            (*frame.ptr).width = target_width as i32;
            (*frame.ptr).height = target_height as i32;
            check(
                ffi::av_frame_get_buffer(frame.ptr, 32),
                "allocating software H.264 frame buffer",
            )?;

            try_set_option((*ctx).priv_data, "aud", "1");
            if codec_name == "h264_nvenc" {
                try_set_option((*ctx).priv_data, "preset", "p4");
                try_set_option((*ctx).priv_data, "tune", "ll");
                try_set_option((*ctx).priv_data, "rc", "cbr");
                try_set_option((*ctx).priv_data, "profile", "baseline");
                try_set_option((*ctx).priv_data, "forced-idr", "1");
            } else {
                try_set_option((*ctx).priv_data, "preset", "ultrafast");
                try_set_option((*ctx).priv_data, "tune", "zerolatency");
                try_set_option((*ctx).priv_data, "profile", "baseline");
                try_set_option((*ctx).priv_data, "forced-idr", "1");
                try_set_option(
                    (*ctx).priv_data,
                    "x264-params",
                    &format!(
                        "keyint={key_interval}:min-keyint={key_interval}:scenecut=0:repeat-headers=1:aud=1"
                    ),
                );
            }
            check(
                ffi::avcodec_open2(ctx, codec, ptr::null_mut()),
                "opening software H.264 encoder",
            )
        };
        if let Err(err) = open_result {
            unsafe {
                let mut packet_to_free = packet;
                let mut ctx_to_free = ctx;
                ffi::av_packet_free(&mut packet_to_free);
                ffi::avcodec_free_context(&mut ctx_to_free);
            }
            return Err(err);
        }

        info!(
            encoder = codec_name,
            width = target_width,
            height = target_height,
            fps,
            bitrate = unsafe { (*ctx).bit_rate },
            "initialized FFmpeg software H.264 encoder"
        );

        Ok(Self {
            target_width,
            target_height,
            fps,
            started_at_ms,
            frame_index: 0,
            codec_ctx: ctx,
            packet,
            sws_ctx: ptr::null_mut(),
            frame,
            force_keyframe: true,
        })
    }

    pub fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    pub fn encode_rgb(&mut self, input: RgbInputFrame) -> Result<Vec<EncodedH264Packet>> {
        if input.width != self.target_width || input.height != self.target_height {
            bail!(
                "software H.264 encoder expected {}x{} RGB input, got {}x{}",
                self.target_width,
                self.target_height,
                input.width,
                input.height
            );
        }
        let expected = input
            .width
            .checked_mul(input.height)
            .and_then(|pixels| pixels.checked_mul(3))
            .context("RGB frame dimensions overflowed")? as usize;
        if input.data.len() < expected {
            bail!(
                "software H.264 encoder got short RGB input: {} < {}",
                input.data.len(),
                expected
            );
        }
        unsafe {
            if self.sws_ctx.is_null() {
                self.sws_ctx = ffi::sws_getContext(
                    input.width as i32,
                    input.height as i32,
                    ffi::AVPixelFormat::AV_PIX_FMT_RGB24,
                    self.target_width as i32,
                    self.target_height as i32,
                    ffi::AVPixelFormat::AV_PIX_FMT_YUV420P,
                    ffi::SwsFlags::SWS_FAST_BILINEAR as i32,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null(),
                );
                if self.sws_ctx.is_null() {
                    bail!("creating RGB to YUV420P scaler for software H.264 failed");
                }
            }
            check(
                ffi::av_frame_make_writable(self.frame.ptr),
                "making software H.264 frame writable",
            )?;
            let src_data = [input.data.as_ptr(), ptr::null(), ptr::null(), ptr::null()];
            let src_stride = [(input.width * 3) as i32, 0, 0, 0];
            let converted = ffi::sws_scale(
                self.sws_ctx,
                src_data.as_ptr(),
                src_stride.as_ptr(),
                0,
                input.height as i32,
                (*self.frame.ptr).data.as_mut_ptr(),
                (*self.frame.ptr).linesize.as_mut_ptr(),
            );
            if converted != self.target_height as i32 {
                bail!(
                    "RGB to YUV420P scaler produced {} rows, expected {}",
                    converted,
                    self.target_height
                );
            }
            (*self.frame.ptr).pts = self.frame_index;
            (*self.frame.ptr).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
            if self.force_keyframe || self.frame_index == 0 {
                mark_frame_for_keyframe(self.frame.as_mut_ptr());
            } else {
                clear_forced_keyframe(self.frame.as_mut_ptr());
            }
        }

        unsafe {
            check(
                ffi::avcodec_send_frame(self.codec_ctx, self.frame.ptr),
                "sending software H.264 frame",
            )?;
        }
        self.force_keyframe = false;
        let packets = self.receive_packets(input.captured_at_ms, input.width, input.height)?;
        self.frame_index += 1;
        Ok(packets)
    }

    fn receive_packets(
        &mut self,
        captured_at_ms: i64,
        source_width: u32,
        source_height: u32,
    ) -> Result<Vec<EncodedH264Packet>> {
        let mut packets = Vec::new();
        loop {
            let ret = unsafe { ffi::avcodec_receive_packet(self.codec_ctx, self.packet) };
            if ret == AVERROR_EAGAIN {
                break;
            }
            check(ret, "receiving software H.264 packet")?;
            let packet = unsafe { &*self.packet };
            if packet.size > 0 && !packet.data.is_null() {
                let payload =
                    unsafe { slice::from_raw_parts(packet.data, packet.size as usize) }.to_vec();
                let pts_ms = if packet.pts == AV_NOPTS_VALUE {
                    captured_at_ms - self.started_at_ms
                } else {
                    packet.pts
                };
                packets.push(EncodedH264Packet {
                    payload,
                    keyframe: packet.flags & ffi::AV_PKT_FLAG_KEY != 0,
                    captured_at_ms,
                    pts_ms,
                    duration_ms: (1000.0 / self.fps).round().max(1.0) as u64,
                    width: self.target_width,
                    height: self.target_height,
                    source_width,
                    source_height,
                });
            }
            unsafe {
                ffi::av_packet_unref(self.packet);
            }
        }
        Ok(packets)
    }
}

impl Drop for SoftwareH264Encoder {
    fn drop(&mut self) {
        unsafe {
            if !self.sws_ctx.is_null() {
                ffi::sws_freeContext(self.sws_ctx);
            }
            if !self.packet.is_null() {
                ffi::av_packet_free(&mut self.packet);
            }
            if !self.codec_ctx.is_null() {
                ffi::avcodec_free_context(&mut self.codec_ctx);
            }
        }
    }
}

fn find_software_h264_encoders() -> impl Iterator<Item = (String, *const ffi::AVCodec)> {
    ["h264_nvenc", "libx264", "libopenh264", "h264"]
        .into_iter()
        .filter_map(|name| {
            let Ok(codec_name) = CString::new(name) else {
                return None;
            };
            let codec = unsafe { ffi::avcodec_find_encoder_by_name(codec_name.as_ptr()) };
            if !codec.is_null() {
                Some((name.to_string(), codec))
            } else {
                None
            }
        })
}

pub struct VaapiUploadH264Encoder {
    target_width: u32,
    target_height: u32,
    fps: f64,
    started_at_ms: i64,
    frame_index: i64,
    codec_ctx: *mut ffi::AVCodecContext,
    packet: *mut ffi::AVPacket,
    sws_ctx: *mut ffi::SwsContext,
    hw_device_ctx: *mut ffi::AVBufferRef,
    hw_frames_ctx: *mut ffi::AVBufferRef,
    sw_frame: AvFrame,
    force_keyframe: bool,
}

unsafe impl Send for VaapiUploadH264Encoder {}

impl VaapiUploadH264Encoder {
    pub fn new(
        target_width: u32,
        target_height: u32,
        fps: f64,
        started_at_ms: i64,
    ) -> Result<Self> {
        let target_width = target_width.max(1);
        let target_height = target_height.max(1);
        let fps = fps.clamp(0.5, 15.0);
        let codec_name = CString::new("h264_vaapi")?;
        let codec = unsafe { ffi::avcodec_find_encoder_by_name(codec_name.as_ptr()) };
        if codec.is_null() {
            bail!("FFmpeg libavcodec does not expose the h264_vaapi encoder");
        }

        let mut hw_device_ctx = ptr::null_mut();
        let hw_frames_ctx;
        let sw_frame = AvFrame::new()?;
        let codec_ctx = unsafe { ffi::avcodec_alloc_context3(codec) };
        if codec_ctx.is_null() {
            bail!("allocating h264_vaapi upload codec context failed");
        }
        let packet = unsafe { ffi::av_packet_alloc() };
        if packet.is_null() {
            unsafe {
                let mut ctx_to_free = codec_ctx;
                ffi::avcodec_free_context(&mut ctx_to_free);
            }
            bail!("allocating H.264 packet failed");
        }

        let device_label = unsafe { create_vaapi_device_context(&mut hw_device_ctx)? };
        unsafe {
            hw_frames_ctx = ffi::av_hwframe_ctx_alloc(hw_device_ctx);
            if hw_frames_ctx.is_null() {
                bail!("allocating FFmpeg VAAPI upload frames context failed");
            }
            let frames_ctx = (*hw_frames_ctx).data as *mut ffi::AVHWFramesContext;
            if frames_ctx.is_null() {
                bail!("FFmpeg VAAPI upload frames context has no backing data");
            }
            (*frames_ctx).format = ffi::AVPixelFormat::AV_PIX_FMT_VAAPI;
            (*frames_ctx).sw_format = ffi::AVPixelFormat::AV_PIX_FMT_NV12;
            (*frames_ctx).width = target_width as i32;
            (*frames_ctx).height = target_height as i32;
            (*frames_ctx).initial_pool_size = 8;
            check(
                ffi::av_hwframe_ctx_init(hw_frames_ctx),
                "initializing FFmpeg VAAPI upload frames context",
            )?;

            (*sw_frame.ptr).format = ffi::AVPixelFormat::AV_PIX_FMT_NV12 as i32;
            (*sw_frame.ptr).width = target_width as i32;
            (*sw_frame.ptr).height = target_height as i32;
            check(
                ffi::av_frame_get_buffer(sw_frame.ptr, 32),
                "allocating VAAPI upload staging frame",
            )?;
        }

        let (fps_num, fps_den) = fps_rational(fps);
        unsafe {
            (*codec_ctx).width = target_width as i32;
            (*codec_ctx).height = target_height as i32;
            (*codec_ctx).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
            (*codec_ctx).framerate = ffi::AVRational {
                num: fps_num,
                den: fps_den,
            };
            (*codec_ctx).pix_fmt = ffi::AVPixelFormat::AV_PIX_FMT_VAAPI;
            (*codec_ctx).max_b_frames = 0;
            (*codec_ctx).gop_size = fps_num.div_euclid(fps_den).max(1);
            (*codec_ctx).keyint_min = (*codec_ctx).gop_size;
            (*codec_ctx).bit_rate = recommended_bitrate(target_width, target_height, fps);
            (*codec_ctx).thread_count = 1;
            (*codec_ctx).hw_frames_ctx = ffi::av_buffer_ref(hw_frames_ctx);
            if (*codec_ctx).hw_frames_ctx.is_null() {
                bail!("copying VAAPI upload frame context for h264_vaapi failed");
            }

            try_set_option((*codec_ctx).priv_data, "aud", "1");
            try_set_option((*codec_ctx).priv_data, "idr_interval", "1");
            try_set_option((*codec_ctx).priv_data, "profile", "constrained_baseline");
            try_set_option((*codec_ctx).priv_data, "rc_mode", "CQP");
            check(
                ffi::avcodec_open2(codec_ctx, codec, ptr::null_mut()),
                "opening h264_vaapi upload encoder",
            )?;
        }

        info!(
            width = target_width,
            height = target_height,
            fps,
            bitrate = unsafe { (*codec_ctx).bit_rate },
            vaapi_device = device_label,
            "initialized FFmpeg CPU-readable to h264_vaapi upload encoder"
        );

        Ok(Self {
            target_width,
            target_height,
            fps,
            started_at_ms,
            frame_index: 0,
            codec_ctx,
            packet,
            sws_ctx: ptr::null_mut(),
            hw_device_ctx,
            hw_frames_ctx,
            sw_frame,
            force_keyframe: true,
        })
    }

    pub fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    pub fn encode_rgb(&mut self, input: RgbInputFrame) -> Result<Vec<EncodedH264Packet>> {
        if input.width != self.target_width || input.height != self.target_height {
            bail!(
                "VAAPI upload encoder expected {}x{} RGB input, got {}x{}",
                self.target_width,
                self.target_height,
                input.width,
                input.height
            );
        }
        let expected = input
            .width
            .checked_mul(input.height)
            .and_then(|pixels| pixels.checked_mul(3))
            .context("RGB frame dimensions overflowed")? as usize;
        if input.data.len() < expected {
            bail!(
                "VAAPI upload encoder got short RGB input: {} < {}",
                input.data.len(),
                expected
            );
        }

        unsafe {
            if self.sws_ctx.is_null() {
                self.sws_ctx = ffi::sws_getContext(
                    input.width as i32,
                    input.height as i32,
                    ffi::AVPixelFormat::AV_PIX_FMT_RGB24,
                    self.target_width as i32,
                    self.target_height as i32,
                    ffi::AVPixelFormat::AV_PIX_FMT_NV12,
                    ffi::SwsFlags::SWS_FAST_BILINEAR as i32,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null(),
                );
                if self.sws_ctx.is_null() {
                    bail!("creating RGB to NV12 scaler for VAAPI upload failed");
                }
            }
            check(
                ffi::av_frame_make_writable(self.sw_frame.ptr),
                "making VAAPI upload staging frame writable",
            )?;
            let src_data = [input.data.as_ptr(), ptr::null(), ptr::null(), ptr::null()];
            let src_stride = [(input.width * 3) as i32, 0, 0, 0];
            let converted = ffi::sws_scale(
                self.sws_ctx,
                src_data.as_ptr(),
                src_stride.as_ptr(),
                0,
                input.height as i32,
                (*self.sw_frame.ptr).data.as_mut_ptr(),
                (*self.sw_frame.ptr).linesize.as_mut_ptr(),
            );
            if converted != self.target_height as i32 {
                bail!(
                    "RGB to NV12 scaler produced {} rows, expected {}",
                    converted,
                    self.target_height
                );
            }
            (*self.sw_frame.ptr).pts = self.frame_index;
            (*self.sw_frame.ptr).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
        }

        let mut hw_frame = AvFrame::new()?;
        unsafe {
            check(
                ffi::av_hwframe_get_buffer(self.hw_frames_ctx, hw_frame.as_mut_ptr(), 0),
                "allocating VAAPI upload hardware frame",
            )?;
            check(
                ffi::av_hwframe_transfer_data(hw_frame.as_mut_ptr(), self.sw_frame.as_ptr(), 0),
                "uploading CPU-readable frame to VAAPI",
            )?;
            (*hw_frame.ptr).pts = self.frame_index;
            (*hw_frame.ptr).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
            if self.force_keyframe || self.frame_index == 0 {
                mark_frame_for_keyframe(hw_frame.as_mut_ptr());
            } else {
                clear_forced_keyframe(hw_frame.as_mut_ptr());
            }
            check(
                ffi::avcodec_send_frame(self.codec_ctx, hw_frame.as_ptr()),
                "sending uploaded VAAPI frame to h264_vaapi",
            )?;
        }
        self.force_keyframe = false;

        let packets = self.receive_packets(input.captured_at_ms, input.width, input.height)?;
        self.frame_index += 1;
        Ok(packets)
    }

    fn receive_packets(
        &mut self,
        captured_at_ms: i64,
        source_width: u32,
        source_height: u32,
    ) -> Result<Vec<EncodedH264Packet>> {
        let mut packets = Vec::new();
        loop {
            let ret = unsafe { ffi::avcodec_receive_packet(self.codec_ctx, self.packet) };
            if ret == AVERROR_EAGAIN {
                break;
            }
            check(ret, "receiving H.264 packet from uploaded h264_vaapi")?;
            let packet = unsafe { &*self.packet };
            if packet.size > 0 && !packet.data.is_null() {
                let payload =
                    unsafe { slice::from_raw_parts(packet.data, packet.size as usize) }.to_vec();
                let pts_ms = if packet.pts == AV_NOPTS_VALUE {
                    captured_at_ms - self.started_at_ms
                } else {
                    packet.pts
                };
                packets.push(EncodedH264Packet {
                    payload,
                    keyframe: packet.flags & ffi::AV_PKT_FLAG_KEY != 0,
                    captured_at_ms,
                    pts_ms,
                    duration_ms: (1000.0 / self.fps).round().max(1.0) as u64,
                    width: self.target_width,
                    height: self.target_height,
                    source_width,
                    source_height,
                });
            }
            unsafe {
                ffi::av_packet_unref(self.packet);
            }
        }
        Ok(packets)
    }
}

impl Drop for VaapiUploadH264Encoder {
    fn drop(&mut self) {
        unsafe {
            if !self.sws_ctx.is_null() {
                ffi::sws_freeContext(self.sws_ctx);
            }
            if !self.packet.is_null() {
                ffi::av_packet_free(&mut self.packet);
            }
            if !self.codec_ctx.is_null() {
                ffi::avcodec_free_context(&mut self.codec_ctx);
            }
            if !self.hw_frames_ctx.is_null() {
                ffi::av_buffer_unref(&mut self.hw_frames_ctx);
            }
            if !self.hw_device_ctx.is_null() {
                ffi::av_buffer_unref(&mut self.hw_device_ctx);
            }
        }
    }
}

pub struct VaapiH264Encoder {
    target_width: u32,
    target_height: u32,
    fps: f64,
    started_at_ms: i64,
    frame_index: i64,
    source_width: u32,
    source_height: u32,
    graph: Option<FilterGraph>,
    codec_ctx: *mut ffi::AVCodecContext,
    packet: *mut ffi::AVPacket,
    force_keyframe: bool,
}

unsafe impl Send for VaapiH264Encoder {}

impl VaapiH264Encoder {
    pub fn new(target_width: u32, target_height: u32, fps: f64, started_at_ms: i64) -> Self {
        Self {
            target_width: target_width.max(1),
            target_height: target_height.max(1),
            fps: fps.clamp(0.5, 15.0),
            started_at_ms,
            frame_index: 0,
            source_width: 0,
            source_height: 0,
            graph: None,
            codec_ctx: ptr::null_mut(),
            packet: ptr::null_mut(),
            force_keyframe: true,
        }
    }

    pub fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    pub fn encode_dmabuf(&mut self, frame: DmaBufInputFrame) -> Result<Vec<EncodedH264Packet>> {
        if frame.width == 0 || frame.height == 0 {
            bail!("refusing zero-sized DMA-BUF frame");
        }
        if self.graph.is_none()
            || self.source_width != frame.width
            || self.source_height != frame.height
        {
            self.graph = Some(FilterGraph::new(
                frame.width,
                frame.height,
                self.target_width,
                self.target_height,
                frame.drm_format,
                self.fps,
            )?);
            self.source_width = frame.width;
            self.source_height = frame.height;
        }

        let sink = {
            let graph = self.graph.as_mut().context("filter graph was not built")?;
            let mut input =
                unsafe { AvFrame::from_dmabuf(&frame, self.frame_index, graph.drm_frames_ctx) }?;
            unsafe {
                check(
                    ffi::av_buffersrc_add_frame_flags(
                        graph.src,
                        input.as_mut_ptr(),
                        ffi::AV_BUFFERSRC_FLAG_KEEP_REF as i32,
                    ),
                    "feeding DMA-BUF frame into FFmpeg filter graph",
                )?;
            }
            graph.sink
        };

        let mut packets = Vec::new();
        loop {
            let mut filtered = AvFrame::new()?;
            let ret = unsafe { ffi::av_buffersink_get_frame(sink, filtered.as_mut_ptr()) };
            if ret == AVERROR_EAGAIN {
                break;
            }
            check(ret, "receiving VAAPI frame from FFmpeg filter graph")?;
            self.ensure_encoder(filtered.as_ptr())?;
            packets.extend(self.encode_filtered_frame(
                filtered.as_mut_ptr(),
                frame.captured_at_ms,
                frame.width,
                frame.height,
            )?);
        }

        self.frame_index += 1;
        Ok(packets)
    }

    fn ensure_encoder(&mut self, frame: *const ffi::AVFrame) -> Result<()> {
        if !self.codec_ctx.is_null() {
            return Ok(());
        }
        let codec_name = CString::new("h264_vaapi")?;
        let codec = unsafe { ffi::avcodec_find_encoder_by_name(codec_name.as_ptr()) };
        if codec.is_null() {
            bail!("FFmpeg libavcodec does not expose the h264_vaapi encoder");
        }
        let ctx = unsafe { ffi::avcodec_alloc_context3(codec) };
        if ctx.is_null() {
            bail!("allocating h264_vaapi codec context failed");
        }
        let packet = unsafe { ffi::av_packet_alloc() };
        if packet.is_null() {
            unsafe {
                let mut ctx_to_free = ctx;
                ffi::avcodec_free_context(&mut ctx_to_free);
            }
            bail!("allocating H.264 packet failed");
        }

        let (fps_num, fps_den) = fps_rational(self.fps);
        unsafe {
            (*ctx).width = self.target_width as i32;
            (*ctx).height = self.target_height as i32;
            (*ctx).time_base = ffi::AVRational {
                num: 1,
                den: FILTER_TIME_BASE_DEN,
            };
            (*ctx).framerate = ffi::AVRational {
                num: fps_num,
                den: fps_den,
            };
            (*ctx).pix_fmt = ffi::AVPixelFormat::AV_PIX_FMT_VAAPI;
            (*ctx).max_b_frames = 0;
            (*ctx).gop_size = fps_num.div_euclid(fps_den).max(1);
            (*ctx).keyint_min = (*ctx).gop_size;
            (*ctx).bit_rate = recommended_bitrate(self.target_width, self.target_height, self.fps);
            (*ctx).thread_count = 1;
            if !(*frame).hw_frames_ctx.is_null() {
                (*ctx).hw_frames_ctx = ffi::av_buffer_ref((*frame).hw_frames_ctx);
                if (*ctx).hw_frames_ctx.is_null() {
                    let mut packet_to_free = packet;
                    ffi::av_packet_free(&mut packet_to_free);
                    let mut ctx_to_free = ctx;
                    ffi::avcodec_free_context(&mut ctx_to_free);
                    bail!("copying VAAPI frame context for h264_vaapi failed");
                }
            } else {
                let mut packet_to_free = packet;
                ffi::av_packet_free(&mut packet_to_free);
                let mut ctx_to_free = ctx;
                ffi::avcodec_free_context(&mut ctx_to_free);
                bail!("FFmpeg filter graph did not produce a VAAPI hardware frame context");
            }
        }

        unsafe {
            try_set_option((*ctx).priv_data, "aud", "1");
            try_set_option((*ctx).priv_data, "idr_interval", "1");
            try_set_option((*ctx).priv_data, "profile", "constrained_baseline");
            try_set_option((*ctx).priv_data, "rc_mode", "CQP");
            check(
                ffi::avcodec_open2(ctx, codec, ptr::null_mut()),
                "opening h264_vaapi encoder",
            )?;
        }

        self.codec_ctx = ctx;
        self.packet = packet;
        info!(
            width = self.target_width,
            height = self.target_height,
            fps = self.fps,
            bitrate = unsafe { (*self.codec_ctx).bit_rate },
            "initialized FFmpeg h264_vaapi encoder"
        );
        Ok(())
    }

    fn encode_filtered_frame(
        &mut self,
        frame: *mut ffi::AVFrame,
        captured_at_ms: i64,
        source_width: u32,
        source_height: u32,
    ) -> Result<Vec<EncodedH264Packet>> {
        unsafe {
            if self.force_keyframe || self.frame_index == 0 {
                mark_frame_for_keyframe(frame);
            } else {
                clear_forced_keyframe(frame);
            }
            check(
                ffi::avcodec_send_frame(self.codec_ctx, frame),
                "sending VAAPI frame to h264_vaapi",
            )?;
        }
        self.force_keyframe = false;
        let mut packets = Vec::new();
        loop {
            let ret = unsafe { ffi::avcodec_receive_packet(self.codec_ctx, self.packet) };
            if ret == AVERROR_EAGAIN {
                break;
            }
            check(ret, "receiving H.264 packet from h264_vaapi")?;
            let packet = unsafe { &*self.packet };
            if packet.size > 0 && !packet.data.is_null() {
                let payload =
                    unsafe { slice::from_raw_parts(packet.data, packet.size as usize) }.to_vec();
                let pts_ms = if packet.pts == AV_NOPTS_VALUE {
                    captured_at_ms - self.started_at_ms
                } else {
                    packet.pts
                };
                packets.push(EncodedH264Packet {
                    payload,
                    keyframe: packet.flags & ffi::AV_PKT_FLAG_KEY != 0,
                    captured_at_ms,
                    pts_ms,
                    duration_ms: (1000.0 / self.fps).round().max(1.0) as u64,
                    width: self.target_width,
                    height: self.target_height,
                    source_width,
                    source_height,
                });
            }
            unsafe {
                ffi::av_packet_unref(self.packet);
            }
        }
        Ok(packets)
    }
}

impl Drop for VaapiH264Encoder {
    fn drop(&mut self) {
        unsafe {
            if !self.packet.is_null() {
                ffi::av_packet_free(&mut self.packet);
            }
            if !self.codec_ctx.is_null() {
                ffi::avcodec_free_context(&mut self.codec_ctx);
            }
        }
    }
}

struct FilterGraph {
    graph: *mut ffi::AVFilterGraph,
    src: *mut ffi::AVFilterContext,
    sink: *mut ffi::AVFilterContext,
    drm_device_ctx: *mut ffi::AVBufferRef,
    drm_frames_ctx: *mut ffi::AVBufferRef,
}

#[derive(Clone, Copy)]
struct FilterGraphConfig {
    source_width: u32,
    source_height: u32,
    target_width: u32,
    target_height: u32,
    drm_format: u32,
    fps: f64,
}

impl FilterGraph {
    fn new(
        source_width: u32,
        source_height: u32,
        target_width: u32,
        target_height: u32,
        drm_format: u32,
        fps: f64,
    ) -> Result<Self> {
        let config = FilterGraphConfig {
            source_width,
            source_height,
            target_width,
            target_height,
            drm_format,
            fps,
        };
        let mut errors = Vec::new();
        for filter_description in vaapi_filter_descriptions(target_width, target_height) {
            let graph = unsafe { ffi::avfilter_graph_alloc() };
            if graph.is_null() {
                bail!("allocating FFmpeg filter graph failed");
            }
            let mut out = Self {
                graph,
                src: ptr::null_mut(),
                sink: ptr::null_mut(),
                drm_device_ctx: ptr::null_mut(),
                drm_frames_ctx: ptr::null_mut(),
            };
            match out.configure(config, &filter_description) {
                Ok(()) => return Ok(out),
                Err(err) => {
                    errors.push(format!("{filter_description}: {err:#}"));
                    drop(out);
                }
            }
        }
        bail!(
            "configuring FFmpeg VAAPI filter graph failed for all filter variants: {}",
            errors.join("; ")
        )
    }

    fn configure(&mut self, config: FilterGraphConfig, filter_description: &str) -> Result<()> {
        let (fps_num, fps_den) = fps_rational(config.fps);
        let sw_format = sw_format_for_drm_fourcc(config.drm_format).with_context(|| {
            format!(
                "unsupported DMA-BUF DRM format {}",
                drm_fourcc_name(config.drm_format)
            )
        })?;
        let buffer = cstring("buffer")?;
        let buffersink = cstring("buffersink")?;
        let src_name = cstring("in")?;
        let sink_name = cstring("out")?;
        let args = cstring(&format!(
            "video_size={}x{}:pix_fmt={}:time_base=1/{}:pixel_aspect=1/1:frame_rate={}/{}",
            config.source_width,
            config.source_height,
            ffi::AVPixelFormat::AV_PIX_FMT_DRM_PRIME as i32,
            FILTER_TIME_BASE_DEN,
            fps_num,
            fps_den
        ))?;
        let drm_device;
        unsafe {
            drm_device = create_drm_device_context(&mut self.drm_device_ctx)?;
            self.drm_frames_ctx = ffi::av_hwframe_ctx_alloc(self.drm_device_ctx);
            if self.drm_frames_ctx.is_null() {
                bail!("allocating FFmpeg DRM hardware frames context failed");
            }
            let frames_ctx = (*self.drm_frames_ctx).data as *mut ffi::AVHWFramesContext;
            if frames_ctx.is_null() {
                bail!("FFmpeg DRM hardware frames context has no backing data");
            }
            (*frames_ctx).format = ffi::AVPixelFormat::AV_PIX_FMT_DRM_PRIME;
            (*frames_ctx).sw_format = sw_format;
            (*frames_ctx).width = config.source_width as i32;
            (*frames_ctx).height = config.source_height as i32;
            (*frames_ctx).initial_pool_size = 0;
            check(
                ffi::av_hwframe_ctx_init(self.drm_frames_ctx),
                "initializing FFmpeg DRM hardware frames context",
            )?;

            let buffer_filter = ffi::avfilter_get_by_name(buffer.as_ptr());
            let sink_filter = ffi::avfilter_get_by_name(buffersink.as_ptr());
            if buffer_filter.is_null() || sink_filter.is_null() {
                bail!("FFmpeg buffer/buffersink filters are unavailable");
            }
            check(
                ffi::avfilter_graph_create_filter(
                    &mut self.src,
                    buffer_filter,
                    src_name.as_ptr(),
                    args.as_ptr(),
                    ptr::null_mut(),
                    self.graph,
                ),
                "creating FFmpeg buffer source",
            )?;
            self.configure_buffer_source_parameters(
                config.source_width,
                config.source_height,
                fps_num,
                fps_den,
            )?;
            check(
                ffi::avfilter_graph_create_filter(
                    &mut self.sink,
                    sink_filter,
                    sink_name.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    self.graph,
                ),
                "creating FFmpeg buffer sink",
            )?;
        }

        let filter_description = cstring(filter_description)?;
        let mut inputs = unsafe { make_inout("out", self.sink)? };
        let mut outputs = unsafe { make_inout("in", self.src)? };
        unsafe {
            let parse_ret = ffi::avfilter_graph_parse_ptr(
                self.graph,
                filter_description.as_ptr(),
                &mut inputs,
                &mut outputs,
                ptr::null_mut(),
            );
            ffi::avfilter_inout_free(&mut inputs);
            ffi::avfilter_inout_free(&mut outputs);
            check(parse_ret, "parsing FFmpeg VAAPI filter graph")?;
            check(
                ffi::avfilter_graph_config(self.graph, ptr::null_mut()),
                "configuring FFmpeg VAAPI filter graph",
            )?;
        }
        info!(
            source_width = config.source_width,
            source_height = config.source_height,
            target_width = config.target_width,
            target_height = config.target_height,
            drm_format = drm_fourcc_name(config.drm_format),
            drm_device,
            filter = filter_description.to_string_lossy().as_ref(),
            "initialized FFmpeg DMA-BUF to VAAPI filter graph"
        );
        Ok(())
    }

    unsafe fn configure_buffer_source_parameters(
        &self,
        source_width: u32,
        source_height: u32,
        fps_num: i32,
        fps_den: i32,
    ) -> Result<()> {
        let params = ffi::av_buffersrc_parameters_alloc();
        if params.is_null() {
            bail!("allocating FFmpeg buffer source parameters failed");
        }
        (*params).format = ffi::AVPixelFormat::AV_PIX_FMT_DRM_PRIME as i32;
        (*params).time_base = ffi::AVRational {
            num: 1,
            den: FILTER_TIME_BASE_DEN,
        };
        (*params).width = source_width as i32;
        (*params).height = source_height as i32;
        (*params).sample_aspect_ratio = ffi::AVRational { num: 1, den: 1 };
        (*params).frame_rate = ffi::AVRational {
            num: fps_num,
            den: fps_den,
        };
        (*params).hw_frames_ctx = ffi::av_buffer_ref(self.drm_frames_ctx);
        if (*params).hw_frames_ctx.is_null() {
            ffi::av_free(params as *mut libc::c_void);
            bail!("copying FFmpeg DRM hardware frames context for buffer source failed");
        }
        let ret = ffi::av_buffersrc_parameters_set(self.src, params);
        ffi::av_buffer_unref(&mut (*params).hw_frames_ctx);
        ffi::av_free(params as *mut libc::c_void);
        check(ret, "configuring FFmpeg buffer source parameters")
    }
}

fn vaapi_filter_descriptions(target_width: u32, target_height: u32) -> Vec<String> {
    let width = target_width.max(1);
    let height = target_height.max(1);
    [
        format!(
            "hwmap=derive_device=vaapi,scale_vaapi=w={width}:h={height}:format=nv12:mode=default"
        ),
        format!("hwmap=derive_device=vaapi,scale_vaapi=w={width}:h={height}:format=nv12:mode=fast"),
        format!("hwmap=derive_device=vaapi,scale_vaapi=w={width}:h={height}:format=nv12"),
    ]
    .into()
}

impl Drop for FilterGraph {
    fn drop(&mut self) {
        unsafe {
            if !self.graph.is_null() {
                ffi::avfilter_graph_free(&mut self.graph);
            }
            if !self.drm_frames_ctx.is_null() {
                ffi::av_buffer_unref(&mut self.drm_frames_ctx);
            }
            if !self.drm_device_ctx.is_null() {
                ffi::av_buffer_unref(&mut self.drm_device_ctx);
            }
        }
    }
}

struct AvFrame {
    ptr: *mut ffi::AVFrame,
}

impl AvFrame {
    fn new() -> Result<Self> {
        let ptr = unsafe { ffi::av_frame_alloc() };
        if ptr.is_null() {
            bail!("allocating FFmpeg frame failed");
        }
        Ok(Self { ptr })
    }

    unsafe fn from_dmabuf(
        input: &DmaBufInputFrame,
        pts: i64,
        hw_frames_ctx: *mut ffi::AVBufferRef,
    ) -> Result<Self> {
        let frame = Self::new()?;
        let duplicated_fd = libc::dup(input.fd);
        if duplicated_fd < 0 {
            bail!("duplicating DMA-BUF fd for FFmpeg failed");
        }

        let descriptor_size = mem::size_of::<ffi::AVDRMFrameDescriptor>();
        let descriptor = ffi::av_mallocz(descriptor_size) as *mut ffi::AVDRMFrameDescriptor;
        if descriptor.is_null() {
            let _ = libc::close(duplicated_fd);
            bail!("allocating AVDRMFrameDescriptor failed");
        }
        (*descriptor).nb_objects = 1;
        (*descriptor).objects[0].fd = duplicated_fd;
        (*descriptor).objects[0].size = input.size;
        (*descriptor).objects[0].format_modifier = input.modifier;
        (*descriptor).nb_layers = 1;
        (*descriptor).layers[0].format = input.drm_format;
        (*descriptor).layers[0].nb_planes = 1;
        (*descriptor).layers[0].planes[0].object_index = 0;
        (*descriptor).layers[0].planes[0].offset = input.offset as isize;
        (*descriptor).layers[0].planes[0].pitch = input.stride as isize;

        let buffer_ref = ffi::av_buffer_create(
            descriptor as *mut u8,
            descriptor_size,
            Some(free_drm_frame_descriptor),
            ptr::null_mut(),
            0,
        );
        if buffer_ref.is_null() {
            free_drm_frame_descriptor(ptr::null_mut(), descriptor as *mut u8);
            bail!("creating FFmpeg DMA-BUF descriptor buffer failed");
        }

        (*frame.ptr).format = ffi::AVPixelFormat::AV_PIX_FMT_DRM_PRIME as i32;
        (*frame.ptr).width = input.width as i32;
        (*frame.ptr).height = input.height as i32;
        (*frame.ptr).pts = pts;
        (*frame.ptr).time_base = ffi::AVRational {
            num: 1,
            den: FILTER_TIME_BASE_DEN,
        };
        (*frame.ptr).data[0] = descriptor as *mut u8;
        (*frame.ptr).buf[0] = buffer_ref;
        (*frame.ptr).hw_frames_ctx = ffi::av_buffer_ref(hw_frames_ctx);
        if (*frame.ptr).hw_frames_ctx.is_null() {
            bail!("copying FFmpeg DRM hardware frames context for input frame failed");
        }
        Ok(frame)
    }

    fn as_ptr(&self) -> *const ffi::AVFrame {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut ffi::AVFrame {
        self.ptr
    }
}

impl Drop for AvFrame {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                ffi::av_frame_free(&mut self.ptr);
            }
        }
    }
}

unsafe extern "C" fn free_drm_frame_descriptor(_opaque: *mut libc::c_void, data: *mut u8) {
    if data.is_null() {
        return;
    }
    let descriptor = data as *mut ffi::AVDRMFrameDescriptor;
    for index in 0..(*descriptor).nb_objects.max(0) as usize {
        let fd = (*descriptor).objects[index].fd;
        if fd >= 0 {
            let _ = libc::close(fd);
            (*descriptor).objects[index].fd = -1;
        }
    }
    ffi::av_free(data as *mut libc::c_void);
}

unsafe fn make_inout(
    name: &str,
    filter_ctx: *mut ffi::AVFilterContext,
) -> Result<*mut ffi::AVFilterInOut> {
    let inout = ffi::avfilter_inout_alloc();
    if inout.is_null() {
        bail!("allocating FFmpeg filter in/out failed");
    }
    let c_name = CString::new(name)?;
    (*inout).name = ffi::av_strdup(c_name.as_ptr());
    if (*inout).name.is_null() {
        ffi::avfilter_inout_free(&mut (inout as *mut _));
        bail!("allocating FFmpeg filter pad name failed");
    }
    (*inout).filter_ctx = filter_ctx;
    (*inout).pad_idx = 0;
    (*inout).next = ptr::null_mut();
    Ok(inout)
}

fn fps_rational(fps: f64) -> (i32, i32) {
    let denominator = 1000u32;
    let numerator = (fps.clamp(0.5, 15.0) * f64::from(denominator))
        .round()
        .max(1.0) as u32;
    let divisor = gcd(numerator, denominator).max(1);
    ((numerator / divisor) as i32, (denominator / divisor) as i32)
}

fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let next = a % b;
        a = b;
        b = next;
    }
    a
}

fn recommended_bitrate(width: u32, height: u32, fps: f64) -> i64 {
    let pixels_per_second = width as f64 * height as f64 * fps.clamp(0.5, 15.0);
    pixels_per_second
        .mul_add(0.09, 500_000.0)
        .clamp(1_000_000.0, 12_000_000.0) as i64
}

const fn drm_fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

fn drm_fourcc_name(format: u32) -> String {
    let bytes = format.to_le_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn sw_format_for_drm_fourcc(format: u32) -> Option<ffi::AVPixelFormat> {
    match format {
        x if x == drm_fourcc(b'X', b'R', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_BGR0),
        x if x == drm_fourcc(b'A', b'R', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_BGRA),
        x if x == drm_fourcc(b'X', b'B', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_RGB0),
        x if x == drm_fourcc(b'A', b'B', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_RGBA),
        x if x == drm_fourcc(b'B', b'G', b'R', b'X') => Some(ffi::AVPixelFormat::AV_PIX_FMT_0RGB),
        x if x == drm_fourcc(b'B', b'G', b'R', b'A') => Some(ffi::AVPixelFormat::AV_PIX_FMT_ARGB),
        x if x == drm_fourcc(b'R', b'G', b'B', b'X') => Some(ffi::AVPixelFormat::AV_PIX_FMT_0BGR),
        x if x == drm_fourcc(b'R', b'G', b'B', b'A') => Some(ffi::AVPixelFormat::AV_PIX_FMT_ABGR),
        x if x == drm_fourcc(b'R', b'G', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_RGB24),
        x if x == drm_fourcc(b'B', b'G', b'2', b'4') => Some(ffi::AVPixelFormat::AV_PIX_FMT_BGR24),
        x if x == drm_fourcc(b'Y', b'U', b'Y', b'V') => {
            Some(ffi::AVPixelFormat::AV_PIX_FMT_YUYV422)
        }
        _ => None,
    }
}

unsafe fn create_drm_device_context(out: &mut *mut ffi::AVBufferRef) -> Result<String> {
    let candidates = drm_device_candidates();
    let mut errors = Vec::new();
    for candidate in candidates {
        if !Path::new(&candidate).exists() {
            continue;
        }
        let candidate_c = cstring(&candidate)?;
        let ret = ffi::av_hwdevice_ctx_create(
            out,
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_DRM,
            candidate_c.as_ptr(),
            ptr::null_mut(),
            0,
        );
        if ret >= 0 {
            return Ok(candidate);
        }
        errors.push(format!("{candidate}: {}", av_error(ret)));
    }

    if errors.is_empty() {
        bail!(
            "creating FFmpeg DRM hardware device context failed: no /dev/dri render or card nodes were found"
        );
    }
    bail!(
        "creating FFmpeg DRM hardware device context failed for probed devices: {}",
        errors.join("; ")
    )
}

unsafe fn create_vaapi_device_context(out: &mut *mut ffi::AVBufferRef) -> Result<String> {
    let candidates = drm_device_candidates();
    let mut errors = Vec::new();
    for candidate in candidates {
        if !Path::new(&candidate).exists() {
            continue;
        }
        let candidate_c = cstring(&candidate)?;
        let ret = ffi::av_hwdevice_ctx_create(
            out,
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
            candidate_c.as_ptr(),
            ptr::null_mut(),
            0,
        );
        if ret >= 0 {
            return Ok(candidate);
        }
        errors.push(format!("{candidate}: {}", av_error(ret)));
    }

    let ret = ffi::av_hwdevice_ctx_create(
        out,
        ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
        ptr::null(),
        ptr::null_mut(),
        0,
    );
    if ret >= 0 {
        return Ok("default VAAPI device".to_string());
    }
    errors.push(format!("default VAAPI device: {}", av_error(ret)));

    bail!(
        "creating FFmpeg VAAPI hardware device context failed for probed devices: {}",
        errors.join("; ")
    )
}

fn drm_device_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(path) = env::var("GLACIALCAST_DRM_DEVICE") {
        candidates.push(path);
    }
    for index in 128..=135 {
        candidates.push(format!("/dev/dri/renderD{index}"));
    }
    for index in 0..=3 {
        candidates.push(format!("/dev/dri/card{index}"));
    }
    candidates
}

unsafe fn try_set_option(object: *mut libc::c_void, key: &str, value: &str) {
    if object.is_null() {
        return;
    }
    let Ok(key) = CString::new(key) else {
        return;
    };
    let Ok(value) = CString::new(value) else {
        return;
    };
    let ret = ffi::av_opt_set(object, key.as_ptr(), value.as_ptr(), 0);
    if ret < 0 {
        warn!(
            key = key.to_string_lossy().as_ref(),
            value = value.to_string_lossy().as_ref(),
            err = %av_error(ret),
            "FFmpeg option was not accepted"
        );
    }
}

unsafe fn mark_frame_for_keyframe(frame: *mut ffi::AVFrame) {
    (*frame).pict_type = ffi::AVPictureType::AV_PICTURE_TYPE_I;
    (*frame).flags |= ffi::AV_FRAME_FLAG_KEY;
}

unsafe fn clear_forced_keyframe(frame: *mut ffi::AVFrame) {
    (*frame).pict_type = ffi::AVPictureType::AV_PICTURE_TYPE_NONE;
    (*frame).flags &= !ffi::AV_FRAME_FLAG_KEY;
}

fn check(ret: i32, context: &str) -> Result<()> {
    if ret < 0 {
        bail!("{context}: {}", av_error(ret));
    }
    Ok(())
}

fn cstring(value: &str) -> Result<CString> {
    CString::new(value).with_context(|| format!("string contains an interior NUL: {value:?}"))
}

fn av_error(code: i32) -> String {
    let mut buf = [0i8; 256];
    let ret = unsafe { ffi::av_strerror(code, buf.as_mut_ptr(), buf.len()) };
    if ret < 0 {
        return format!("FFmpeg error {code}");
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}
