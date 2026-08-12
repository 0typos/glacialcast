//! Compact cursor events carried inside native encrypted cursor objects.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Maximum encoded cursor batch size before native object encryption.
pub const MAX_CURSOR_PLAINTEXT_LEN: usize = 4 * 1024 * 1024;
/// Maximum width or height of an RGBA cursor bitmap.
pub const MAX_CURSOR_BITMAP_SIDE: u32 = 512;

const CURSOR_BATCH_HEADER_LEN: usize = 14;
const CURSOR_EVENT_LEN: usize = 33;
const CURSOR_BITMAP_HEADER_LEN: usize = 20;

/// Errors produced while encoding or validating cursor data.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CursorError {
    /// The cursor payload exceeded [`MAX_CURSOR_PLAINTEXT_LEN`].
    #[error("cursor payload exceeds its size limit")]
    TooLarge,
    /// The cursor payload or its authenticated context is malformed.
    #[error("cursor payload is malformed")]
    Malformed,
}

/// One cursor state change on the shared media timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorEvent {
    /// Event time in native stream timestamp ticks.
    pub timestamp: u64,
    /// Horizontal source coordinate in millionths of a pixel.
    pub x_micropixels: i64,
    /// Vertical source coordinate in millionths of a pixel.
    pub y_micropixels: i64,
    /// Whether the cursor should be rendered after this event.
    pub visible: bool,
    /// Stable identity of the active bitmap, or zero while hidden.
    pub bitmap_id: u64,
    /// New RGBA bitmap data when the bitmap changed or was refreshed.
    pub bitmap: Option<CursorBitmap>,
}

/// An unpremultiplied, row-major RGBA cursor image and hotspot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBitmap {
    /// Bitmap width in pixels.
    pub width: u32,
    /// Bitmap height in pixels.
    pub height: u32,
    /// Horizontal hotspot offset in pixels.
    pub hotspot_x: i32,
    /// Vertical hotspot offset in pixels.
    pub hotspot_y: i32,
    /// Exactly `width * height * 4` row-major RGBA bytes.
    pub rgba: Vec<u8>,
}

/// Ordered cursor events captured for one source and time range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBatch {
    /// Captured source width used to validate and scale coordinates.
    pub source_width: u32,
    /// Captured source height used to validate and scale coordinates.
    pub source_height: u32,
    /// Nonempty events ordered by ascending timestamp.
    pub events: Vec<CursorEvent>,
}

/// Public object metadata used to bind a decoded cursor batch to its stream.
#[derive(Debug, Clone, Copy)]
pub struct CursorContext {
    /// Stream to which the cursor object belongs.
    pub stream_id: Uuid,
    /// Capture epoch to which the cursor object belongs.
    pub epoch_id: Uuid,
    /// Monotonic stream-object sequence number.
    pub sequence: u64,
    /// First permitted event time in native stream timestamp ticks.
    pub start_timestamp: u64,
    /// Captured source width expected in the decoded batch.
    pub source_width: u32,
    /// Captured source height expected in the decoded batch.
    pub source_height: u32,
}

/// Validates and encodes a cursor batch for native object encryption.
///
/// # Errors
///
/// Returns an error when the batch or its context violates the cursor format.
pub fn encode_cursor_batch(
    context: CursorContext,
    batch: &CursorBatch,
) -> Result<Vec<u8>, CursorError> {
    validate_cursor_batch(batch)?;
    validate_cursor_context(batch, context)?;
    let encoded_len = encoded_len(batch)?;
    let event_count = u16::try_from(batch.events.len()).map_err(|_| CursorError::TooLarge)?;
    let mut bytes = Vec::with_capacity(encoded_len);
    bytes.extend_from_slice(b"GCC1");
    bytes.extend_from_slice(&batch.source_width.to_be_bytes());
    bytes.extend_from_slice(&batch.source_height.to_be_bytes());
    bytes.extend_from_slice(&event_count.to_be_bytes());
    for event in &batch.events {
        bytes.extend_from_slice(&event.timestamp.to_be_bytes());
        bytes.extend_from_slice(&event.x_micropixels.to_be_bytes());
        bytes.extend_from_slice(&event.y_micropixels.to_be_bytes());
        bytes.push(u8::from(event.visible) | (u8::from(event.bitmap.is_some()) << 1));
        bytes.extend_from_slice(&event.bitmap_id.to_be_bytes());
        if let Some(bitmap) = &event.bitmap {
            bytes.extend_from_slice(&bitmap.width.to_be_bytes());
            bytes.extend_from_slice(&bitmap.height.to_be_bytes());
            bytes.extend_from_slice(&bitmap.hotspot_x.to_be_bytes());
            bytes.extend_from_slice(&bitmap.hotspot_y.to_be_bytes());
            let rgba_len = u32::try_from(bitmap.rgba.len()).map_err(|_| CursorError::TooLarge)?;
            bytes.extend_from_slice(&rgba_len.to_be_bytes());
            bytes.extend_from_slice(&bitmap.rgba);
        }
    }
    Ok(bytes)
}

/// Decodes and validates a cursor batch from a decrypted native object.
///
/// # Errors
///
/// Returns an error for oversized, truncated, noncanonical, or context-mismatched data.
pub fn decode_cursor_batch(
    context: CursorContext,
    bytes: &[u8],
) -> Result<CursorBatch, CursorError> {
    if bytes.len() > MAX_CURSOR_PLAINTEXT_LEN {
        return Err(CursorError::TooLarge);
    }
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != b"GCC1" {
        return Err(CursorError::Malformed);
    }
    let source_width = reader.u32()?;
    let source_height = reader.u32()?;
    let event_count = reader.u16()?;
    if reader.remaining() < usize::from(event_count).saturating_mul(CURSOR_EVENT_LEN) {
        return Err(CursorError::Malformed);
    }
    let mut events = Vec::with_capacity(usize::from(event_count));
    for _ in 0..event_count {
        let timestamp = reader.u64()?;
        let x_micropixels = reader.i64()?;
        let y_micropixels = reader.i64()?;
        let flags = reader.u8()?;
        if flags & !0b11 != 0 {
            return Err(CursorError::Malformed);
        }
        let bitmap_id = reader.u64()?;
        let bitmap = if flags & 0b10 != 0 {
            let width = reader.u32()?;
            let height = reader.u32()?;
            let hotspot_x = reader.i32()?;
            let hotspot_y = reader.i32()?;
            let rgba_len = usize::try_from(reader.u32()?).map_err(|_| CursorError::Malformed)?;
            Some(CursorBitmap {
                width,
                height,
                hotspot_x,
                hotspot_y,
                rgba: reader.take(rgba_len)?.to_vec(),
            })
        } else {
            None
        };
        events.push(CursorEvent {
            timestamp,
            x_micropixels,
            y_micropixels,
            visible: flags & 1 != 0,
            bitmap_id,
            bitmap,
        });
    }
    if !reader.is_empty() {
        return Err(CursorError::Malformed);
    }
    let batch = CursorBatch {
        source_width,
        source_height,
        events,
    };
    validate_cursor_batch(&batch)?;
    validate_cursor_context(&batch, context)?;
    Ok(batch)
}

fn validate_cursor_batch(batch: &CursorBatch) -> Result<(), CursorError> {
    if batch.source_width == 0
        || batch.source_height == 0
        || batch.source_width > u32::from(u16::MAX)
        || batch.source_height > u32::from(u16::MAX)
        || batch.events.is_empty()
    {
        return Err(CursorError::Malformed);
    }
    let max_x = i64::from(batch.source_width) * 1_000_000;
    let max_y = i64::from(batch.source_height) * 1_000_000;
    let mut previous = None;
    for event in &batch.events {
        if previous.is_some_and(|value| event.timestamp < value) {
            return Err(CursorError::Malformed);
        }
        previous = Some(event.timestamp);
        if event.visible {
            if !(0..=max_x).contains(&event.x_micropixels)
                || !(0..=max_y).contains(&event.y_micropixels)
            {
                return Err(CursorError::Malformed);
            }
        } else if event.x_micropixels != 0 || event.y_micropixels != 0 || event.bitmap.is_some() {
            return Err(CursorError::Malformed);
        }
        if let Some(bitmap) = &event.bitmap {
            let expected_len = usize::try_from(bitmap.width)
                .ok()
                .and_then(|width| {
                    usize::try_from(bitmap.height)
                        .ok()
                        .and_then(|height| width.checked_mul(height))
                })
                .and_then(|pixels| pixels.checked_mul(4));
            if event.bitmap_id == 0
                || bitmap.width == 0
                || bitmap.height == 0
                || bitmap.width > MAX_CURSOR_BITMAP_SIDE
                || bitmap.height > MAX_CURSOR_BITMAP_SIDE
                || bitmap.hotspot_x < 0
                || bitmap.hotspot_y < 0
                || bitmap.hotspot_x.unsigned_abs() >= bitmap.width
                || bitmap.hotspot_y.unsigned_abs() >= bitmap.height
                || expected_len != Some(bitmap.rgba.len())
            {
                return Err(CursorError::Malformed);
            }
        }
    }
    encoded_len(batch)?;
    Ok(())
}

fn validate_cursor_context(batch: &CursorBatch, context: CursorContext) -> Result<(), CursorError> {
    if context.stream_id.is_nil()
        || context.epoch_id.is_nil()
        || batch.source_width != context.source_width
        || batch.source_height != context.source_height
        || batch.events.first().map(|event| event.timestamp) != Some(context.start_timestamp)
    {
        return Err(CursorError::Malformed);
    }
    let _ = context.sequence;
    Ok(())
}

fn encoded_len(batch: &CursorBatch) -> Result<usize, CursorError> {
    u16::try_from(batch.events.len()).map_err(|_| CursorError::TooLarge)?;
    let mut length = CURSOR_BATCH_HEADER_LEN;
    for event in &batch.events {
        length = length
            .checked_add(CURSOR_EVENT_LEN)
            .ok_or(CursorError::TooLarge)?;
        if let Some(bitmap) = &event.bitmap {
            length = length
                .checked_add(CURSOR_BITMAP_HEADER_LEN)
                .and_then(|value| value.checked_add(bitmap.rgba.len()))
                .ok_or(CursorError::TooLarge)?;
        }
        if length > MAX_CURSOR_PLAINTEXT_LEN {
            return Err(CursorError::TooLarge);
        }
    }
    Ok(length)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CursorError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CursorError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CursorError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, CursorError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CursorError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CursorError::Malformed)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, CursorError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CursorError::Malformed)?,
        ))
    }
    fn i32(&mut self) -> Result<i32, CursorError> {
        Ok(i32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CursorError::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, CursorError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CursorError::Malformed)?,
        ))
    }
    fn i64(&mut self) -> Result<i64, CursorError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CursorError::Malformed)?,
        ))
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CursorContext, CursorBatch) {
        let stream_id = Uuid::new_v4();
        let epoch_id = Uuid::new_v4();
        let batch = CursorBatch {
            source_width: 1920,
            source_height: 1080,
            events: vec![CursorEvent {
                timestamp: 90_000,
                x_micropixels: 10_000_000,
                y_micropixels: 20_000_000,
                visible: true,
                bitmap_id: 7,
                bitmap: Some(CursorBitmap {
                    width: 2,
                    height: 2,
                    hotspot_x: 1,
                    hotspot_y: 1,
                    rgba: vec![255; 16],
                }),
            }],
        };
        let context = CursorContext {
            stream_id,
            epoch_id,
            sequence: 3,
            start_timestamp: 90_000,
            source_width: 1920,
            source_height: 1080,
        };
        (context, batch)
    }

    #[test]
    fn round_trip_is_canonical() {
        let (context, batch) = fixture();
        let encoded = encode_cursor_batch(context, &batch).unwrap();
        assert_eq!(decode_cursor_batch(context, &encoded).unwrap(), batch);
    }

    #[test]
    fn rejects_truncation_trailing_data_and_wrong_context() {
        let (context, batch) = fixture();
        let encoded = encode_cursor_batch(context, &batch).unwrap();
        assert_eq!(
            decode_cursor_batch(context, &encoded[..encoded.len() - 1]),
            Err(CursorError::Malformed)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_cursor_batch(context, &trailing),
            Err(CursorError::Malformed)
        );
        let wrong = CursorContext {
            source_width: 1,
            ..context
        };
        assert_eq!(
            decode_cursor_batch(wrong, &encoded),
            Err(CursorError::Malformed)
        );
    }

    #[test]
    fn rejects_oversized_payload_before_parsing() {
        let (context, _) = fixture();
        let oversized = vec![0; MAX_CURSOR_PLAINTEXT_LEN + 1];
        assert_eq!(
            decode_cursor_batch(context, &oversized),
            Err(CursorError::TooLarge)
        );
    }
}
