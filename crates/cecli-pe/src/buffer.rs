//! Growable byte buffer with a reading/writing cursor.
//!
//! Port of `Mono.Cecil.PE/ByteBuffer.cs`. Unlike [`cecli_core::io::ByteWriter`],
//! which is append-only, this buffer keeps a movable position so callers can
//! patch previously written bytes (used heavily by the metadata layer).

use cecli_core::{Error, Result};

/// Cursor-based growable byte buffer, mirroring Cecil's `ByteBuffer`.
#[derive(Debug, Default, Clone)]
pub struct ByteBuffer {
    data: Vec<u8>,
    length: usize,
    position: usize,
}

impl ByteBuffer {
    /// An empty buffer.
    pub fn new() -> Self {
        ByteBuffer::default()
    }

    /// A zero-filled buffer of `length` bytes.
    pub fn zeroed(length: usize) -> Self {
        ByteBuffer {
            data: vec![0; length],
            length,
            position: 0,
        }
    }

    /// Wraps an existing buffer; the initial length is the full slice length.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let length = data.len();
        ByteBuffer {
            data,
            length,
            position: 0,
        }
    }

    /// Wraps a borrowed slice into an owned buffer.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn set_position(&mut self, position: usize) -> Result<()> {
        if position > self.length {
            return Err(Error::bad_image(format!(
                "seek {position} beyond buffer length {}",
                self.length
            )));
        }
        self.position = position;
        Ok(())
    }

    /// Number of valid (written or wrapped) bytes.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The valid portion of the buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.length]
    }

    /// Consumes the buffer, returning all bytes ever written.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn advance(&mut self, count: isize) -> Result<()> {
        let target = self.position as isize + count;
        if target < 0 || target as usize > self.length {
            return Err(Error::bad_image(format!(
                "advance {count} from {} out of bounds (length {})",
                self.position, self.length
            )));
        }
        self.position = target as usize;
        Ok(())
    }

    /// Moves the cursor to a 4-byte boundary relative to the buffer start.
    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let rem = self.position % alignment;
        if rem != 0 {
            self.set_position(self.position + (alignment - rem))?;
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.position + n > self.length {
            return Err(Error::bad_image(format!(
                "read {n} bytes at {} with only {} valid",
                self.position, self.length
            )));
        }
        let s = &self.data[self.position..self.position + n];
        self.position += n;
        Ok(s)
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        self.take(n)
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn i16(&mut self) -> Result<i16> {
        Ok(self.u16()? as i16)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }


    /// Mutable access to the valid portion, for in-place patching.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.length]
    }
    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }

    /// ECMA-335 II §23.2 compressed unsigned integer.
    pub fn compressed_u32(&mut self) -> Result<u32> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            return Ok(first as u32);
        }
        if first & 0x40 == 0 {
            Ok((((first & !0x80) as u32) << 8) | self.read_byte()? as u32)
        } else {
            Ok((((first & !0xC0) as u32) << 24)
                | (self.read_byte()? as u32) << 16
                | (self.read_byte()? as u32) << 8
                | self.read_byte()? as u32)
        }
    }

    /// ECMA-335 II §23.2 compressed signed integer.
    pub fn compressed_i32(&mut self) -> Result<i32> {
        if self.position >= self.length {
            return Err(Error::bad_image(format!(
                "compressed int read at {} beyond length {}",
                self.position, self.length
            )));
        }
        let first = self.data[self.position];
        let u = self.compressed_u32()?;
        let v = (u >> 1) as i32;
        if u & 1 == 0 {
            return Ok(v);
        }
        match first & 0xC0 {
            0x00 | 0x40 => Ok(v - 0x40),
            0x80 => Ok(v - 0x2000),
            _ => Ok(v - 0x1000_0000),
        }
    }

    fn ensure_capacity(&mut self, desired: usize) {
        if self.position + desired > self.data.len() {
            self.data.resize(self.position + desired, 0);
        }
    }


    pub fn write_byte(&mut self, value: u8) {
        self.ensure_capacity(1);
        self.data[self.position] = value;
        self.position += 1;
        if self.position > self.length {
            self.length = self.position;
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.ensure_capacity(bytes.len());
        self.data[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
        if self.position > self.length {
            self.length = self.position;
        }
    }

    /// Reserves `n` bytes of zeros at the cursor without writing values.
    pub fn write_zeros(&mut self, n: usize) {
        self.ensure_capacity(n);
        self.position += n;
        if self.position > self.length {
            self.length = self.position;
        }
    }

    pub fn u16_write(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn i16_write(&mut self, value: i16) {
        self.u16_write(value as u16);
    }

    pub fn u32_write(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn i32_write(&mut self, value: i32) {
        self.u32_write(value as u32);
    }

    pub fn u64_write(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn i64_write(&mut self, value: i64) {
        self.u64_write(value as u64);
    }

    pub fn f32_write(&mut self, value: f32) {
        self.u32_write(value.to_bits());
    }

    pub fn f64_write(&mut self, value: f64) {
        self.u64_write(value.to_bits());
    }

    /// ECMA-335 II §23.2 compressed unsigned integer.
    pub fn compressed_u32_write(&mut self, value: u32) {
        if value < 0x80 {
            self.write_byte(value as u8);
        } else if value < 0x4000 {
            self.write_byte((0x80 | (value >> 8)) as u8);
            self.write_byte((value & 0xff) as u8);
        } else {
            self.write_byte(((value >> 24) | 0xc0) as u8);
            self.write_byte(((value >> 16) & 0xff) as u8);
            self.write_byte(((value >> 8) & 0xff) as u8);
            self.write_byte((value & 0xff) as u8);
        }
    }

    /// ECMA-335 II §23.2 compressed signed integer (port of the
    /// System.Reflection.Metadata algorithm Cecil uses).
    pub fn compressed_i32_write(&mut self, value: i32) {
        const B6: i32 = (1 << 6) - 1;
        const B13: i32 = (1 << 13) - 1;
        const B28: i32 = (1 << 28) - 1;

        // sign_mask is 0xffffffff for negative values, 0 otherwise.
        let sign_mask = value >> 31;

        if value & !B6 == sign_mask & !B6 {
            let n = ((value & B6) << 1) | (sign_mask & 1);
            self.write_byte(n as u8);
        } else if value & !B13 == sign_mask & !B13 {
            let n = ((value & B13) << 1) | (sign_mask & 1);
            self.u16_write((0x8000u16 | (n as u16)).swap_bytes());
        } else if value & !B28 == sign_mask & !B28 {
            let n = ((value & B28) << 1) | (sign_mask & 1);
            self.u32_write((0xC000_0000u32 | n as u32).swap_bytes());
        } else {
            // Out of the encodable -2^28..2^28-1 range; like
            // `cecli_core::io::ByteWriter::compressed_i32`, encode the low
            // bits in the widest envelope instead of panicking.
            let rotated = ((value as u32) << 1) | (((value >> 31) as u32) & 1);
            self.u32_write((0xC000_0000u32 | (rotated & 0x1FFF_FFFF)).swap_bytes());
        }
    }

    /// Copies the valid contents of `other` starting at this buffer's cursor.
    pub fn write_buffer(&mut self, other: &ByteBuffer) {
        self.write_bytes(other.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut b = ByteBuffer::new();
        b.u32_write(0xDEAD_BEEF);
        b.compressed_u32_write(0x3FFF);
        b.i64_write(-5);
        b.set_position(0).unwrap();
        assert_eq!(b.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(b.compressed_u32().unwrap(), 0x3FFF);
        assert_eq!(b.i64().unwrap(), -5);
        assert_eq!(b.position(), b.length());
    }

    #[test]
    fn patch_after_write() {
        let mut b = ByteBuffer::new();
        b.u32_write(1);
        let pos = b.position();
        b.u32_write(2);
        b.data[pos..pos + 4].copy_from_slice(&9u32.to_le_bytes());
        b.set_position(pos).unwrap();
        assert_eq!(b.u32().unwrap(), 9);
    }

    #[test]
    fn compressed_i32_matches_core() {
        let cases = [
            0i32, 1, -1, 63, -64, 8191, -8192, 268_435_455, -268_435_456, 134_217_727, -134_217_728,
        ];
        for &c in &cases {
            let mut b = ByteBuffer::new();
            b.compressed_i32_write(c);
            let encoded = b.as_slice().to_vec();

            let mut core = cecli_core::io::ByteWriter::new();
            core.compressed_i32(c);

            let mut back = ByteBuffer::from_slice(&encoded);
            assert_eq!(back.compressed_i32().unwrap(), c, "decode mismatch for {c}");
            // The envelope must agree with the shared core encoder.
            assert_eq!(
                encoded, core.as_slice(),
                "envelope mismatch for {c}: ours {encoded:?} vs core {:?}",
                core.as_slice()
            );
        }
    }

    #[test]
    fn out_of_bounds_read_is_error() {
        let mut b = ByteBuffer::from_slice(&[1, 2, 3]);
        assert!(b.u32().is_err());
        assert!(b.advance(-10).is_err());
    }
}
