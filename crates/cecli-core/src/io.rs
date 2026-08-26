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

    /// Compressed unsigned integer, bit-exact port of Mono.Cecil's
    /// `ByteBuffer.ReadCompressedUInt32`: envelopes `0-0x7F`,
    /// `10xx xxxx+1` (15 bits), `11xx xxxx+3` (30 bits).
    pub fn compressed_u32(&mut self) -> Result<u32> {
        let first = self.u8()?;
        if first & 0x80 == 0 {
            return Ok(first as u32);
        }
        if first & 0x40 == 0 {
            return Ok((((first & !0x80) as u32) << 8) | self.u8()? as u32);
        }
        Ok(
            (((first & !0xC0) as u32) << 24)
                | (self.u8()? as u32) << 16
                | (self.u8()? as u32) << 8
                | self.u8()? as u32,
        )
    }

    /// Compressed signed integer, bit-exact port of Mono.Cecil's
    /// `ByteBuffer.ReadCompressedInt32`: magnitude halves the decoded
    /// unsigned value, then subtracts an envelope-specific bias.
    pub fn compressed_i32(&mut self) -> Result<i32> {
        if self.is_empty() {
            return Err(Error::bad_image("compressed integer at end of stream"));
        }
        let first = self.bytes()[self.position()];
        let u = self.compressed_u32()?;
        let v = (u >> 1) as i32;
        if u & 1 == 0 {
            return Ok(v);
        }
        Ok(match first & 0xC0 {
            0 | 0x40 => v - 0x40,
            0x80 => v - 0x2000,
            _ => v.wrapping_sub(0x10000000),
        })
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

    /// Compressed unsigned integer, bit-exact port of Mono.Cecil's
    /// `ByteBuffer.WriteCompressedUInt32` (values `>= 0x4000_0000` lose the
    /// top two bits exactly like upstream).
    pub fn compressed_u32(&mut self, v: u32) {
        if v < 0x80 {
            self.u8(v as u8);
        } else if v < 0x4000 {
            self.u8((0x80 | (v >> 8)) as u8);
            self.u8((v & 0xff) as u8);
        } else {
            self.u8(((v >> 24) | 0xC0) as u8);
            self.u8(((v >> 16) & 0xff) as u8);
            self.u8(((v >> 8) & 0xff) as u8);
            self.u8((v & 0xff) as u8);
        }
    }

    /// Compressed signed integer, bit-exact port of Mono.Cecil's
    /// `ByteBuffer.WriteCompressedInt32` (valid range `-2^28 .. 2^28-1`;
    /// out-of-range values saturate into the largest envelope instead of
    /// panicking, since our writer API is infallible).
    pub fn compressed_i32(&mut self, value: i32) {
        const B6: i32 = (1 << 6) - 1;
        const B13: i32 = (1 << 13) - 1;
        const B28: i32 = (1 << 28) - 1;
        let sign_mask = value >> 31;
        if (value & !B6) == (sign_mask & !B6) {
            let n = ((value & B6) << 1) | (sign_mask & 1);
            self.u8(n as u8);
        } else if (value & !B13) == (sign_mask & !B13) {
            let n = ((value & B13) << 1) | (sign_mask & 1);
            let val = (0x8000u16 | n as u16).to_be_bytes();
            self.bytes(&val);
        } else {
            let n = (((value & B28) << 1) | (sign_mask & 1)) as u32;
            let val = 0xC000_0000u32 | n;
            self.bytes(&val.to_be_bytes());
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
