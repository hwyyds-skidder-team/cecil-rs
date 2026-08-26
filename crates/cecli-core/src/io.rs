//! Little-endian binary cursor primitives shared by the PE and metadata layers.

use crate::error::{Error, Result};

/// Reading cursor over a byte slice.
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ByteReader { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        ByteReader { data, pos }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(Error::bad_image(format!("seek {pos} beyond {len}", len = self.data.len())));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::bad_image(format!(
                "read {n} bytes at {} with only {} remaining",
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
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
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }

    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }

    /// Reads exactly `n` raw bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    /// ECMA-335 II §23.2 compressed unsigned integer.
    pub fn compressed_u32(&mut self) -> Result<u32> {
        let first = self.u8()?;
        if first & 0x80 == 0 {
            return Ok(first as u32);
        }
        if first & 0xC0 == 0x80 {
            Ok((((first & 0x3F) as u32) << 8) | self.u8()? as u32)
        } else {
            let hi = ((first & 0x1F) as u32) << 24;
            Ok(hi | (self.u8()? as u32) << 16 | (self.u8()? as u32) << 8 | self.u8()? as u32)
        }
    }

    /// ECMA-335 II §23.2 compressed signed integer.
    pub fn compressed_i32(&mut self) -> Result<i32> {
        let first = self.u8()?;
        let raw: u32 = if first & 0x80 == 0 {
            first as u32
        } else if first & 0xC0 == 0x80 {
            (((first & 0x3F) as u32) << 8) | self.u8()? as u32
        } else {
            ((first & 0x1F) as u32) << 24
                | (self.u8()? as u32) << 16
                | (self.u8()? as u32) << 8
                | self.u8()? as u32
        };
        // Envelope width comes from the first byte's prefix pattern, not the
        // payload magnitude: signed encodings are not canonical.
        let width_bits: u32 = if first & 0x80 == 0 {
            7
        } else if first & 0xC0 == 0x80 {
            14
        } else {
            29
        };
        let val = (raw >> 1) as i32;
        if raw & 1 != 0 && width_bits < 32 {
            Ok(val | (-1i32) << (width_bits - 1))
        } else {
            Ok(val)
        }
    }

    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let rem = self.pos % alignment;
        if rem != 0 {
            self.seek(self.pos + (alignment - rem))?;
        }
        Ok(())
    }
}

/// Writing cursor over a growable buffer.
#[derive(Default)]
pub struct ByteWriter {
    buf: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        ByteWriter { buf: Vec::new() }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn position(&self) -> usize {
        self.buf.len()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn i8(&mut self, v: i8) {
        self.u8(v as u8);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i16(&mut self, v: i16) {
        self.u16(v as u16);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }

    pub fn f32(&mut self, v: f32) {
        self.u32(v.to_bits());
    }

    pub fn f64(&mut self, v: f64) {
        self.u64(v.to_bits());
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    /// Overwrites 4 bytes at `pos` (used for back-patching).
    pub fn patch_u32_at(&mut self, pos: usize, v: u32) {
        self.buf[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// ECMA-335 II §23.2 compressed unsigned integer.
    pub fn compressed_u32(&mut self, mut v: u32) {
        if v < 0x80 {
            self.u8(v as u8);
        } else if v < 0x4000 {
            self.u8(((v >> 8) | 0x80) as u8);
            self.u8((v & 0xFF) as u8);
        } else if v < 0x2000_0000 {
            self.u8(((v >> 24) | 0xC0) as u8);
            self.u8((v >> 16) as u8);
            self.u8((v >> 8) as u8);
            self.u8(v as u8);
        } else {
            // Encoded as five bytes: 0xC0 prefix byte then full 32-bit value.
            self.u8(0xC0);
            self.u32(v);
            // The branch above never runs because values >= 0x2000_0000 fall here.
            let _ = &mut v;
        }
    }

    /// ECMA-335 II §23.2 compressed signed integer.
    pub fn compressed_i32(&mut self, v: i32) {
        // Rotate left through carry: payload = (v << 1) | sign_bit, masked to the
        // chosen envelope; the value's range (not the rotated magnitude) picks it.
        let rotated = ((v as u32) << 1) | (((v >> 31) as u32) & 1);
        if (-64..=63).contains(&v) {
            self.u8((rotated & 0x7F) as u8);
        } else if (-8192..=8191).contains(&v) {
            self.u8(((rotated >> 8) & 0x3F | 0x80) as u8);
            self.u8((rotated & 0xFF) as u8);
        } else {
            self.u8((((rotated >> 24) & 0x1F) | 0xC0) as u8);
            self.u8((rotated >> 16) as u8);
            self.u8((rotated >> 8) as u8);
            self.u8(rotated as u8);
        }
    }

    pub fn align(&mut self, alignment: usize) {
        while self.buf.len() % alignment != 0 {
            self.u8(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_uint_roundtrip() {
        let cases = [0u32, 1, 0x7F, 0x80, 0xFF, 0x100, 0x3FFF, 0x4000, 0xFFFF, 0x1FFF_FFFF - 1, 0x1FFF_FFFF];
        for &c in &cases {
            let mut w = ByteWriter::new();
            w.compressed_u32(c);
            let encoded = w.into_vec();
            let mut r = ByteReader::new(&encoded);
            assert_eq!(r.compressed_u32().unwrap(), c, "case {c:#x}");
            assert_eq!(r.position(), encoded.len());
        }
    }

    #[test]
    fn compressed_int_roundtrip() {
        let cases = [0i32, 1, -1, 63, -64, 8191, -8192, 268_435_455, -268_435_456, 134_217_727, -134_217_728];
        for &c in &cases {
            let mut w = ByteWriter::new();
            w.compressed_i32(c);
            let encoded = w.into_vec();
            let mut r = ByteReader::new(&encoded);
            assert_eq!(r.compressed_i32().unwrap(), c, "case {c}");
        }
    }
    #[test]
    fn primitive_roundtrip() {
        let mut w = ByteWriter::new();
        w.u16(0xABCD);
        w.i64(-5);
        w.f32(1.5);
        w.bytes(b"xy");
        let data = w.into_vec();
        let mut r = ByteReader::new(&data);
        assert_eq!(r.u16().unwrap(), 0xABCD);
        assert_eq!(r.i64().unwrap(), -5);
        assert_eq!(r.f32().unwrap(), 1.5);
        assert_eq!(r.read_bytes(2).unwrap(), b"xy");
    }

    #[test]
    fn overflow_is_error() {
        let mut r = ByteReader::new(&[1u8]);
        assert!(r.u16().is_err());
    }

    #[test]
    fn align_works() {
        let mut r = ByteReader::at(&[0u8; 8], 3);
        r.align(4).unwrap();
        assert_eq!(r.position(), 4);
        let mut w = ByteWriter::new();
        w.u8(1);
        w.align(4);
        assert_eq!(w.len(), 4);
    }
}
