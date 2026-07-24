use aes::Aes128;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use thiserror::Error;
use uuid::Uuid;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;

pub const DASH_FORMAT_VERSION: u16 = 1;
pub const MEDIA_TIMESCALE: u32 = 90_000;
pub const DEFAULT_FRAME_DURATION: u32 = MEDIA_TIMESCALE;
pub const DEFAULT_SEGMENT_FRAMES: u16 = 4;
pub const MAX_MEDIA_PAYLOAD: usize = 32 * 1024 * 1024;
pub const MAX_CURSOR_PAYLOAD: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DashError {
    #[error("H264 access unit does not contain an Annex-B NAL unit")]
    EmptyAccessUnit,
    #[error("H264 SPS must contain at least four bytes")]
    InvalidSps,
    #[error("H264 PPS must not be empty")]
    InvalidPps,
    #[error("media payload exceeds {MAX_MEDIA_PAYLOAD} bytes")]
    MediaTooLarge,
    #[error("cursor payload exceeds {MAX_CURSOR_PAYLOAD} bytes")]
    CursorTooLarge,
    #[error("CENC auxiliary data exceeds one-byte saiz representation")]
    AuxiliaryInfoTooLarge,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("HKDF output length is invalid")]
    Hkdf,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("viewer key must decode to 32 bytes, got {0}")]
    InvalidViewerKey(usize),
    #[error("invalid DASH epoch descriptor")]
    InvalidEpochDescriptor,
}

pub type Result<T> = std::result::Result<T, DashError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochDescriptor {
    pub format_version: u16,
    pub stream_id: Uuid,
    pub epoch_id: Uuid,
    pub key_id: [u8; 16],
    pub width: u16,
    pub height: u16,
    pub codec: String,
    pub timescale: u32,
    pub segment_frames: u16,
    pub availability_start_time: String,
}

impl EpochDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != DASH_FORMAT_VERSION
            || self.stream_id.is_nil()
            || self.epoch_id.is_nil()
            || self.key_id != *self.epoch_id.as_bytes()
            || self.width == 0
            || self.height == 0
            || self.timescale != MEDIA_TIMESCALE
            || self.segment_frames == 0
            || !self.codec.starts_with("avc1.")
            || self.codec.len() > 32
            || self.availability_start_time.len() > 64
        {
            return Err(DashError::InvalidEpochDescriptor);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let descriptor: Self = serde_json::from_slice(bytes)?;
        descriptor.validate()?;
        Ok(descriptor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeys {
    pub key_id: [u8; 16],
    pub cenc_key: [u8; 16],
    pub cursor_key: [u8; 32],
    pub authentication_key: [u8; 32],
}

impl EpochKeys {
    pub fn derive(viewer_key: &[u8; 32], stream_id: Uuid, epoch_id: Uuid) -> Result<Self> {
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"glacialcast epoch key salt");
        salt_hasher.update(stream_id.as_bytes());
        salt_hasher.update(epoch_id.as_bytes());
        let salt = salt_hasher.finalize();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), viewer_key);
        let mut material = [0u8; 80];
        hkdf.expand(b"glacialcast dash epoch keys v1", &mut material)
            .map_err(|_| DashError::Hkdf)?;

        let mut cenc_key = [0u8; 16];
        cenc_key.copy_from_slice(&material[..16]);
        let mut cursor_key = [0u8; 32];
        cursor_key.copy_from_slice(&material[16..48]);
        let mut authentication_key = [0u8; 32];
        authentication_key.copy_from_slice(&material[48..80]);

        Ok(Self {
            key_id: *epoch_id.as_bytes(),
            cenc_key,
            cursor_key,
            authentication_key,
        })
    }

    pub fn key_id_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key_id)
    }

    pub fn cenc_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.cenc_key)
    }
}

pub fn random_viewer_key_b64() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    URL_SAFE_NO_PAD.encode(key)
}

pub fn decode_viewer_key_b64(encoded: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded.trim())?;
    if decoded.len() != 32 {
        return Err(DashError::InvalidViewerKey(decoded.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorEvent {
    pub timestamp: u64,
    pub x_micropixels: i64,
    pub y_micropixels: i64,
    pub visible: bool,
    pub bitmap_id: u64,
    pub bitmap: Option<CursorBitmap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBitmap {
    pub width: u32,
    pub height: u32,
    pub hotspot_x: i32,
    pub hotspot_y: i32,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBatch {
    pub source_width: u32,
    pub source_height: u32,
    pub events: Vec<CursorEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCursorBatch {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct CursorContext {
    pub stream_id: Uuid,
    pub epoch_id: Uuid,
    pub sequence: u64,
    pub start_timestamp: u64,
    pub source_width: u32,
    pub source_height: u32,
}

pub fn encrypt_cursor_batch(
    keys: &EpochKeys,
    context: CursorContext,
    batch: &CursorBatch,
) -> Result<EncryptedCursorBatch> {
    validate_cursor_batch(batch)?;
    let plaintext = serde_json::to_vec(batch)?;
    if plaintext.len() > MAX_CURSOR_PAYLOAD {
        return Err(DashError::CursorTooLarge);
    }
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new((&keys.cursor_key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &cursor_aad(context),
            },
        )
        .map_err(|_| DashError::Crypto)?;
    Ok(EncryptedCursorBatch { nonce, ciphertext })
}

pub fn decrypt_cursor_batch(
    keys: &EpochKeys,
    context: CursorContext,
    encrypted: &EncryptedCursorBatch,
) -> Result<CursorBatch> {
    let cipher = Aes256Gcm::new((&keys.cursor_key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            Payload {
                msg: &encrypted.ciphertext,
                aad: &cursor_aad(context),
            },
        )
        .map_err(|_| DashError::Crypto)?;
    let batch: CursorBatch = serde_json::from_slice(&plaintext)?;
    validate_cursor_batch(&batch)?;
    Ok(batch)
}

fn validate_cursor_batch(batch: &CursorBatch) -> Result<()> {
    if batch.source_width == 0 || batch.source_height == 0 {
        return Err(DashError::CursorTooLarge);
    }
    for event in &batch.events {
        if let Some(bitmap) = &event.bitmap {
            let expected = usize::try_from(bitmap.width)
                .ok()
                .and_then(|width| {
                    usize::try_from(bitmap.height)
                        .ok()
                        .and_then(|height| width.checked_mul(height))
                })
                .and_then(|pixels| pixels.checked_mul(4));
            if expected != Some(bitmap.rgba.len()) {
                return Err(DashError::CursorTooLarge);
            }
        }
    }
    Ok(())
}

fn cursor_aad(context: CursorContext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 8 + 8 + 4 + 4 + 16);
    aad.extend_from_slice(b"glacial-cursor-v1");
    aad.extend_from_slice(context.stream_id.as_bytes());
    aad.extend_from_slice(context.epoch_id.as_bytes());
    aad.extend_from_slice(&context.sequence.to_be_bytes());
    aad.extend_from_slice(&context.start_timestamp.to_be_bytes());
    aad.extend_from_slice(&context.source_width.to_be_bytes());
    aad.extend_from_slice(&context.source_height.to_be_bytes());
    aad
}

#[derive(Debug, Clone)]
pub struct AvcConfig {
    pub width: u16,
    pub height: u16,
    pub sps: Vec<u8>,
    pub pps: Vec<u8>,
}

impl AvcConfig {
    pub fn codec_string(&self) -> Result<String> {
        if self.sps.len() < 4 {
            return Err(DashError::InvalidSps);
        }
        Ok(format!(
            "avc1.{:02x}{:02x}{:02x}",
            self.sps[1], self.sps[2], self.sps[3]
        ))
    }
}

#[derive(Debug, Clone)]
pub struct FragmentInput<'a> {
    pub sequence: u32,
    pub decode_time: u64,
    pub duration: u32,
    pub keyframe: bool,
    pub annex_b: &'a [u8],
    pub iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFragment {
    pub bytes: Vec<u8>,
    pub encrypted_sample: Vec<u8>,
    pub subsamples: Vec<Subsample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subsample {
    pub clear_bytes: u16,
    pub encrypted_bytes: u32,
}

pub fn build_encrypted_init_segment(config: &AvcConfig, key_id: [u8; 16]) -> Result<Vec<u8>> {
    if config.sps.len() < 4 {
        return Err(DashError::InvalidSps);
    }
    if config.pps.is_empty() {
        return Err(DashError::InvalidPps);
    }

    let ftyp = mp4_box(*b"ftyp", |out| {
        out.extend_from_slice(b"iso6");
        put_u32(out, 1);
        out.extend_from_slice(b"iso6");
        out.extend_from_slice(b"dash");
        out.extend_from_slice(b"cmfc");
        out.extend_from_slice(b"mp41");
    });

    let moov = mp4_box(*b"moov", |moov| {
        moov.extend(full_box(*b"mvhd", 0, 0, |out| {
            put_u32(out, 0);
            put_u32(out, 0);
            put_u32(out, MEDIA_TIMESCALE);
            put_u32(out, 0);
            put_u32(out, 0x0001_0000);
            put_u16(out, 0x0100);
            put_u16(out, 0);
            out.extend_from_slice(&[0; 8]);
            write_unity_matrix(out);
            out.extend_from_slice(&[0; 24]);
            put_u32(out, 2);
        }));
        moov.extend(build_track(config, key_id));
        moov.extend(mp4_box(*b"mvex", |out| {
            out.extend(full_box(*b"trex", 0, 0, |trex| {
                put_u32(trex, 1);
                put_u32(trex, 1);
                put_u32(trex, DEFAULT_FRAME_DURATION);
                put_u32(trex, 0);
                put_u32(trex, 0);
            }));
        }));
    });

    let mut output = Vec::with_capacity(ftyp.len() + moov.len());
    output.extend(ftyp);
    output.extend(moov);
    Ok(output)
}

fn build_track(config: &AvcConfig, key_id: [u8; 16]) -> Vec<u8> {
    mp4_box(*b"trak", |trak| {
        trak.extend(full_box(*b"tkhd", 0, 0x000007, |out| {
            put_u32(out, 0);
            put_u32(out, 0);
            put_u32(out, 1);
            put_u32(out, 0);
            put_u32(out, 0);
            out.extend_from_slice(&[0; 8]);
            put_u16(out, 0);
            put_u16(out, 0);
            put_u16(out, 0);
            put_u16(out, 0);
            write_unity_matrix(out);
            put_u32(out, u32::from(config.width) << 16);
            put_u32(out, u32::from(config.height) << 16);
        }));
        trak.extend(mp4_box(*b"mdia", |mdia| {
            mdia.extend(full_box(*b"mdhd", 0, 0, |out| {
                put_u32(out, 0);
                put_u32(out, 0);
                put_u32(out, MEDIA_TIMESCALE);
                put_u32(out, 0);
                put_u16(out, 0x55c4);
                put_u16(out, 0);
            }));
            mdia.extend(full_box(*b"hdlr", 0, 0, |out| {
                put_u32(out, 0);
                out.extend_from_slice(b"vide");
                out.extend_from_slice(&[0; 12]);
                out.extend_from_slice(b"GlacialCast Video\0");
            }));
            mdia.extend(mp4_box(*b"minf", |minf| {
                minf.extend(full_box(*b"vmhd", 0, 1, |out| {
                    out.extend_from_slice(&[0; 8]);
                }));
                minf.extend(mp4_box(*b"dinf", |dinf| {
                    dinf.extend(full_box(*b"dref", 0, 0, |out| {
                        put_u32(out, 1);
                        out.extend(full_box(*b"url ", 0, 1, |_| {}));
                    }));
                }));
                minf.extend(build_sample_table(config, key_id));
            }));
        }));
    })
}

fn build_sample_table(config: &AvcConfig, key_id: [u8; 16]) -> Vec<u8> {
    mp4_box(*b"stbl", |stbl| {
        stbl.extend(full_box(*b"stsd", 0, 0, |out| {
            put_u32(out, 1);
            out.extend(build_encrypted_sample_entry(config, key_id));
        }));
        stbl.extend(full_box(*b"stts", 0, 0, |out| put_u32(out, 0)));
        stbl.extend(full_box(*b"stsc", 0, 0, |out| put_u32(out, 0)));
        stbl.extend(full_box(*b"stsz", 0, 0, |out| {
            put_u32(out, 0);
            put_u32(out, 0);
        }));
        stbl.extend(full_box(*b"stco", 0, 0, |out| put_u32(out, 0)));
    })
}

fn build_encrypted_sample_entry(config: &AvcConfig, key_id: [u8; 16]) -> Vec<u8> {
    mp4_box(*b"encv", |entry| {
        entry.extend_from_slice(&[0; 6]);
        put_u16(entry, 1);
        entry.extend_from_slice(&[0; 16]);
        put_u16(entry, config.width);
        put_u16(entry, config.height);
        put_u32(entry, 0x0048_0000);
        put_u32(entry, 0x0048_0000);
        put_u32(entry, 0);
        put_u16(entry, 1);
        entry.extend_from_slice(&[0; 32]);
        put_u16(entry, 0x0018);
        put_u16(entry, u16::MAX);

        entry.extend(mp4_box(*b"avcC", |avcc| {
            avcc.push(1);
            avcc.push(config.sps[1]);
            avcc.push(config.sps[2]);
            avcc.push(config.sps[3]);
            avcc.push(0xff);
            avcc.push(0xe1);
            put_u16(avcc, config.sps.len() as u16);
            avcc.extend_from_slice(&config.sps);
            avcc.push(1);
            put_u16(avcc, config.pps.len() as u16);
            avcc.extend_from_slice(&config.pps);
        }));

        entry.extend(mp4_box(*b"sinf", |sinf| {
            sinf.extend(mp4_box(*b"frma", |out| out.extend_from_slice(b"avc1")));
            sinf.extend(full_box(*b"schm", 0, 0, |out| {
                out.extend_from_slice(b"cenc");
                put_u32(out, 0x0001_0000);
            }));
            sinf.extend(mp4_box(*b"schi", |schi| {
                schi.extend(full_box(*b"tenc", 0, 0, |out| {
                    out.push(0);
                    out.push(0);
                    out.push(1);
                    out.push(16);
                    out.extend_from_slice(&key_id);
                }));
            }));
        }));
    })
}

pub fn build_encrypted_fragment(
    cenc_key: &[u8; 16],
    input: FragmentInput<'_>,
) -> Result<MediaFragment> {
    if input.annex_b.len() > MAX_MEDIA_PAYLOAD {
        return Err(DashError::MediaTooLarge);
    }
    let (mut sample, ranges) = annex_b_to_avcc(input.annex_b)?;
    let mut cipher = Aes128Ctr::new(cenc_key.into(), (&input.iv).into());
    let mut subsamples = Vec::with_capacity(ranges.len());
    for range in ranges {
        let clear_bytes = 5u16;
        let encrypted_len = range.end.saturating_sub(range.start);
        cipher.apply_keystream(&mut sample[range]);
        subsamples.push(Subsample {
            clear_bytes,
            encrypted_bytes: encrypted_len as u32,
        });
    }

    let auxiliary_size = 16usize
        .saturating_add(2)
        .saturating_add(subsamples.len().saturating_mul(6));
    if auxiliary_size > u8::MAX as usize || subsamples.len() > u16::MAX as usize {
        return Err(DashError::AuxiliaryInfoTooLarge);
    }

    let mut moof = mp4_box(*b"moof", |moof| {
        moof.extend(full_box(*b"mfhd", 0, 0, |out| {
            put_u32(out, input.sequence);
        }));
        moof.extend(mp4_box(*b"traf", |traf| {
            traf.extend(full_box(*b"tfhd", 0, 0x020000, |out| {
                put_u32(out, 1);
            }));
            traf.extend(full_box(*b"tfdt", 1, 0, |out| {
                put_u64(out, input.decode_time);
            }));
            traf.extend(full_box(*b"trun", 0, 0x000701, |out| {
                put_u32(out, 1);
                put_i32(out, 0);
                put_u32(out, input.duration);
                put_u32(out, sample.len() as u32);
                put_u32(
                    out,
                    if input.keyframe {
                        0x0200_0000
                    } else {
                        0x0101_0000
                    },
                );
            }));
            traf.extend(full_box(*b"saiz", 0, 0, |out| {
                out.push(auxiliary_size as u8);
                put_u32(out, 1);
            }));
            traf.extend(full_box(*b"saio", 0, 0, |out| {
                put_u32(out, 1);
                put_u32(out, 0);
            }));
            traf.extend(full_box(*b"senc", 0, 0x000002, |out| {
                put_u32(out, 1);
                out.extend_from_slice(&input.iv);
                put_u16(out, subsamples.len() as u16);
                for subsample in &subsamples {
                    put_u16(out, subsample.clear_bytes);
                    put_u32(out, subsample.encrypted_bytes);
                }
            }));
        }));
    });

    patch_fragment_offsets(&mut moof)?;
    let mdat = mp4_box(*b"mdat", |out| out.extend_from_slice(&sample));
    let mut bytes = Vec::with_capacity(moof.len() + mdat.len());
    bytes.extend_from_slice(&moof);
    bytes.extend_from_slice(&mdat);

    Ok(MediaFragment {
        bytes,
        encrypted_sample: sample,
        subsamples,
    })
}

fn patch_fragment_offsets(moof: &mut [u8]) -> Result<()> {
    let trun = find_box(moof, *b"trun").ok_or(DashError::EmptyAccessUnit)?;
    let data_offset = i32::try_from(moof.len() + 8).map_err(|_| DashError::MediaTooLarge)?;
    moof[trun + 16..trun + 20].copy_from_slice(&data_offset.to_be_bytes());

    let saio = find_box(moof, *b"saio").ok_or(DashError::EmptyAccessUnit)?;
    let senc = find_box(moof, *b"senc").ok_or(DashError::EmptyAccessUnit)?;
    let auxiliary_offset = u32::try_from(senc + 16).map_err(|_| DashError::MediaTooLarge)?;
    moof[saio + 16..saio + 20].copy_from_slice(&auxiliary_offset.to_be_bytes());
    Ok(())
}

fn annex_b_to_avcc(access_unit: &[u8]) -> Result<(Vec<u8>, Vec<std::ops::Range<usize>>)> {
    let nals = annex_b_nals(access_unit);
    if nals.is_empty() {
        return Err(DashError::EmptyAccessUnit);
    }
    let total = nals
        .iter()
        .fold(0usize, |sum, nal| sum.saturating_add(4 + nal.len()));
    if total > MAX_MEDIA_PAYLOAD {
        return Err(DashError::MediaTooLarge);
    }
    let mut sample = Vec::with_capacity(total);
    let mut encrypted_ranges = Vec::with_capacity(nals.len());
    for nal in nals {
        put_u32(&mut sample, nal.len() as u32);
        sample.extend_from_slice(nal);
        if nal.len() > 1 {
            let start = sample.len() - nal.len() + 1;
            encrypted_ranges.push(start..sample.len());
        }
    }
    Ok((sample, encrypted_ranges))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentTimelineEntry {
    pub number: u64,
    pub start: u64,
    pub duration: u64,
}

#[derive(Debug, Clone)]
pub struct MpdConfig<'a> {
    pub stream_id: Uuid,
    pub epoch_id: Uuid,
    pub key_id: [u8; 16],
    pub width: u16,
    pub height: u16,
    pub codec: &'a str,
    pub availability_start_time: &'a str,
    pub time_shift_buffer_depth_seconds: u64,
    pub segments: &'a [SegmentTimelineEntry],
    pub dynamic: bool,
}

pub fn build_mpd(config: &MpdConfig<'_>) -> String {
    let mpd_type = if config.dynamic { "dynamic" } else { "static" };
    let minimum_update = if config.dynamic {
        " minimumUpdatePeriod=\"PT1S\" suggestedPresentationDelay=\"PT2S\""
    } else {
        ""
    };
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" \
         xmlns:cenc=\"urn:mpeg:cenc:2013\" \
         profiles=\"urn:mpeg:dash:profile:isoff-live:2011\" \
         type=\"{mpd_type}\" availabilityStartTime=\"{}\" \
         timeShiftBufferDepth=\"PT{}S\" minBufferTime=\"PT1S\"{minimum_update}>\n\
         <Period id=\"{}\" start=\"PT0S\">\n\
         <AdaptationSet id=\"1\" contentType=\"video\" mimeType=\"video/mp4\" \
         segmentAlignment=\"true\" startWithSAP=\"1\">\n\
         <ContentProtection schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\" \
         value=\"cenc\" cenc:default_KID=\"{}\"/>\n\
         <Representation id=\"video\" bandwidth=\"1000000\" codecs=\"{}\" \
         width=\"{}\" height=\"{}\">\n\
         <SegmentTemplate timescale=\"{}\" startNumber=\"{}\" \
         initialization=\"epochs/{}/init.mp4\" \
         media=\"epochs/{}/media/$Number$.m4s\">\n\
         <SegmentTimeline>\n",
        xml_escape(config.availability_start_time),
        config.time_shift_buffer_depth_seconds,
        config.stream_id,
        format_uuid(config.key_id),
        xml_escape(config.codec),
        config.width,
        config.height,
        MEDIA_TIMESCALE,
        config
            .segments
            .first()
            .map(|segment| segment.number)
            .unwrap_or(1),
        config.epoch_id,
        config.epoch_id,
    );
    for segment in config.segments {
        let _ = writeln!(
            xml,
            "<S t=\"{}\" d=\"{}\"/>",
            segment.start, segment.duration
        );
    }
    xml.push_str(
        "</SegmentTimeline>\n</SegmentTemplate>\n</Representation>\n\
         </AdaptationSet>\n</Period>\n</MPD>\n",
    );
    xml
}

pub fn authenticate_object(
    authentication_key: &[u8; 32],
    header: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(authentication_key).expect("HMAC accepts any key");
    mac.update(header);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

pub fn verify_object_authentication(
    authentication_key: &[u8; 32],
    header: &[u8],
    payload: &[u8],
    tag: &[u8; 32],
) -> bool {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(authentication_key).expect("HMAC accepts any key");
    mac.update(header);
    mac.update(payload);
    mac.verify_slice(tag).is_ok()
}

fn mp4_box(kind: [u8; 4], build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(&kind);
    build(&mut output);
    let size = u32::try_from(output.len()).expect("MVP MP4 box must fit in 32 bits");
    output[..4].copy_from_slice(&size.to_be_bytes());
    output
}

fn full_box(kind: [u8; 4], version: u8, flags: u32, build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    mp4_box(kind, |out| {
        out.push(version);
        out.extend_from_slice(&flags.to_be_bytes()[1..]);
        build(out);
    })
}

fn find_box(bytes: &[u8], kind: [u8; 4]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == kind)
        .and_then(|kind_offset| kind_offset.checked_sub(4))
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_unity_matrix(out: &mut Vec<u8>) {
    for value in [0x0001_0000u32, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
        put_u32(out, value);
    }
}

fn format_uuid(bytes: [u8; 16]) -> String {
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config() -> AvcConfig {
        AvcConfig {
            width: 1280,
            height: 720,
            sps: vec![0x67, 0x42, 0xc0, 0x1f, 0xda, 0x01, 0x40, 0x16],
            pps: vec![0x68, 0xce, 0x06, 0xe2],
        }
    }

    #[test]
    fn epoch_keys_are_stable_and_scoped() {
        let viewer_key = [7u8; 32];
        let stream = Uuid::from_u128(1);
        let epoch = Uuid::from_u128(2);
        let first = EpochKeys::derive(&viewer_key, stream, epoch).unwrap();
        let second = EpochKeys::derive(&viewer_key, stream, epoch).unwrap();
        let other = EpochKeys::derive(&viewer_key, stream, Uuid::from_u128(3)).unwrap();

        assert_eq!(first, second);
        assert_ne!(first.cenc_key, other.cenc_key);
        assert_eq!(first.key_id, *epoch.as_bytes());
    }

    #[test]
    fn cursor_batch_authenticates_timing_and_dimensions() {
        let keys = EpochKeys::derive(&[9u8; 32], Uuid::from_u128(1), Uuid::from_u128(2)).unwrap();
        let context = CursorContext {
            stream_id: Uuid::from_u128(1),
            epoch_id: Uuid::from_u128(2),
            sequence: 4,
            start_timestamp: 90_000,
            source_width: 1920,
            source_height: 1080,
        };
        let batch = CursorBatch {
            source_width: 1920,
            source_height: 1080,
            events: vec![CursorEvent {
                timestamp: 91_500,
                x_micropixels: 40_500_000,
                y_micropixels: 20_250_000,
                visible: true,
                bitmap_id: 7,
                bitmap: None,
            }],
        };
        let encrypted = encrypt_cursor_batch(&keys, context, &batch).unwrap();

        assert_eq!(
            decrypt_cursor_batch(&keys, context, &encrypted).unwrap(),
            batch
        );
        let wrong_context = CursorContext {
            sequence: 5,
            ..context
        };
        assert!(decrypt_cursor_batch(&keys, wrong_context, &encrypted).is_err());
    }

    #[test]
    fn init_segment_declares_avc_and_common_encryption() {
        let init = build_encrypted_init_segment(&fixture_config(), [3u8; 16]).unwrap();

        for marker in [
            b"ftyp", b"moov", b"encv", b"avcC", b"sinf", b"cenc", b"tenc",
        ] {
            assert!(init.windows(4).any(|window| window == marker));
        }
        assert!(init.windows(16).any(|window| window == [3u8; 16]));

        let tenc = find_box(&init, *b"tenc").unwrap();
        assert_eq!(
            &init[tenc + 8..tenc + 16],
            &[0, 0, 0, 0, 0, 0, 1, 16],
            "version/flags, reserved, pattern, protected, and IV-size fields"
        );
    }

    #[test]
    fn media_fragment_encrypts_nal_payload_but_not_length_or_header() {
        let access_unit = [
            0, 0, 0, 1, 0x65, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1, 0x06, 9, 10, 11,
        ];
        let fragment = build_encrypted_fragment(
            &[4u8; 16],
            FragmentInput {
                sequence: 1,
                decode_time: 0,
                duration: 90_000,
                keyframe: true,
                annex_b: &access_unit,
                iv: [5u8; 16],
            },
        )
        .unwrap();

        assert_eq!(&fragment.encrypted_sample[..5], &[0, 0, 0, 9, 0x65]);
        assert_ne!(&fragment.encrypted_sample[5..13], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(fragment.subsamples.len(), 2);
        for marker in [
            b"moof", b"traf", b"trun", b"senc", b"saiz", b"saio", b"mdat",
        ] {
            assert!(fragment.bytes.windows(4).any(|window| window == marker));
        }
    }

    #[test]
    fn mpd_declares_cenc_timeline_and_epoch_paths() {
        let stream = Uuid::from_u128(1);
        let epoch = Uuid::from_u128(2);
        let mpd = build_mpd(&MpdConfig {
            stream_id: stream,
            epoch_id: epoch,
            key_id: *epoch.as_bytes(),
            width: 1280,
            height: 720,
            codec: "avc1.42c01f",
            availability_start_time: "2026-01-01T00:00:00Z",
            time_shift_buffer_depth_seconds: 1800,
            segments: &[
                SegmentTimelineEntry {
                    number: 7,
                    start: 0,
                    duration: 360_000,
                },
                SegmentTimelineEntry {
                    number: 8,
                    start: 360_000,
                    duration: 360_000,
                },
            ],
            dynamic: true,
        });

        assert!(mpd.contains("type=\"dynamic\""));
        assert!(mpd.contains("value=\"cenc\""));
        assert!(mpd.contains(&format!("cenc:default_KID=\"{epoch}\"")));
        assert!(mpd.contains("startNumber=\"7\""));
        assert!(mpd.contains("<S t=\"360000\" d=\"360000\"/>"));
    }

    #[test]
    fn object_authentication_detects_header_and_payload_changes() {
        let key = [11u8; 32];
        let tag = authenticate_object(&key, b"header", b"payload");

        assert!(verify_object_authentication(
            &key, b"header", b"payload", &tag
        ));
        assert!(!verify_object_authentication(
            &key, b"other", b"payload", &tag
        ));
        assert!(!verify_object_authentication(
            &key, b"header", b"other", &tag
        ));
    }
}
