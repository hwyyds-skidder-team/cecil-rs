//! Parsing and emitting the BSJB metadata root: the magic signature, the
//! runtime version string, and the stream directory locating the individual
//! heaps (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`, optionally `#Pdb`).
//!
//! Layout (ECMA-335 II §24.2.1):
//!
//! ```text
//! u32  signature ("BSJB")
//! u16  major version
//! u16  minor version
//! u32  reserved
//! u32  version string length (NUL terminated, padded to a multiple of 4)
//! ...  version bytes
//! u16  flags
//! u16  number of streams
//! repeated per stream: u32 offset, u32 size, NUL-padded name
//! ```

use cecli_core::io::ByteReader;
use cecli_core::{Error, Result};

/// The `"BSJB"` magic signature at the start of every metadata root.
pub const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// Directory entry for one stream inside the metadata root.
///
/// `offset` is relative to the start of the metadata root, exactly as stored
/// on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    /// Byte offset of the stream payload, relative to the root start.
    pub offset: u32,
    /// Payload size in bytes (excluding inter-stream alignment padding).
    pub size: u32,
    /// Stream name, e.g. `#~`, `#Strings`, `#US`.
    pub name: String,
}

/// Parsed metadata root header: everything before the stream payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHeader {
    /// Major version of the root format (always 1 in practice).
    pub major_version: u16,
    /// Minor version of the root format.
    pub minor_version: u16,
    /// Runtime version string, e.g. `v4.0.30319`.
    pub version: String,
    /// Reserved flags field (always 0 in practice).
    pub flags: u16,
    /// Stream directory in on-disk order.
    pub streams: Vec<StreamHeader>,
}

impl RootHeader {
    /// Returns the header of the named stream, if present.
    pub fn stream(&self, name: &str) -> Option<&StreamHeader> {
        self.streams.iter().find(|s| s.name == name)
    }
}

/// Parses the BSJB root header from the start of `data`.
///
/// Stream payload bounds are validated lazily via [`stream_slice`].
pub fn parse_root(data: &[u8]) -> Result<RootHeader> {
    let mut r = ByteReader::new(data);
    if r.u32()? != METADATA_SIGNATURE {
        return Err(Error::bad_image(
            "invalid metadata signature (expected \"BSJB\")",
        ));
    }
    let major_version = r.u16()?;
    let minor_version = r.u16()?;
    let _reserved = r.u32()?;

    let version_length = r.u32()? as usize;
    if version_length > r.remaining() {
        return Err(Error::bad_image(format!(
            "version string length {} exceeds remaining {} bytes",
            version_length,
            r.remaining()
        )));
    }
    let version_bytes = r.read_bytes(version_length)?;
    let end = version_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(version_length);
    let version = String::from_utf8_lossy(&version_bytes[..end]).into_owned();

    let flags = r.u16()?;
    let stream_count = r.u16()? as usize;
    if stream_count > r.remaining() / 8 {
        return Err(Error::bad_image(format!(
            "stream count {} exceeds available stream directory",
            stream_count
        )));
    }

    let mut streams = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        let offset = r.u32()?;
        let size = r.u32()?;
        // Stream name: NUL-terminated, padded so the next entry starts on a
        // 4-byte boundary.
        let start = r.position();
        let len = data[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::bad_image("unterminated stream name"))?;
        let name = String::from_utf8_lossy(&data[start..start + len]).into_owned();
        r.seek((start + len + 1 + 3) & !3)?;
        streams.push(StreamHeader { offset, size, name });
    }

    Ok(RootHeader {
        major_version,
        minor_version,
        version,
        flags,
        streams,
    })
}

/// Returns the payload slice of `header` within the root `data`, validating
/// that it lies entirely inside the root.
pub fn stream_slice<'a>(data: &'a [u8], header: &StreamHeader) -> Result<&'a [u8]> {
    let start = header.offset as usize;
    let end = match start.checked_add(header.size as usize) {
        Some(e) => e,
        None => return Err(Error::bad_image("stream range overflows")),
    };
    if end > data.len() {
        return Err(Error::bad_image(format!(
            "stream {:?} [{}, {}) lies outside metadata root of {} bytes",
            header.name,
            start,
            end,
            data.len()
        )));
    }
    Ok(&data[start..end])
}

/// Serializes a complete BSJB root: header followed by the given stream
/// payloads in order, each payload preceded by its directory entry and
/// aligned to a 4-byte boundary.
pub fn write_root(version: &str, streams: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = cecli_core::io::ByteWriter::new();
    w.u32(METADATA_SIGNATURE);
    w.u16(1); // major
    w.u16(1); // minor
    w.u32(0); // reserved

    let version_bytes = version.as_bytes();
    let padded_version_len = (version_bytes.len() + 1 + 3) & !3;
    w.u32(padded_version_len as u32);
    let mut padded = vec![0u8; padded_version_len];
    padded[..version_bytes.len()].copy_from_slice(version_bytes);
    w.bytes(&padded);

    w.u16(0); // flags
    w.u16(streams.len() as u16);

    // Stream data begins right after the directory; compute the offsets.
    let directory_size: usize = streams.iter().map(|(n, _)| 8 + padded_len(n)).sum();
    let mut offset = w.len() + directory_size;
    for (name, data) in streams {
        w.u32(offset as u32);
        w.u32(data.len() as u32);
        let mut name_bytes = vec![0u8; padded_len(name)];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());
        w.bytes(&name_bytes);
        offset += data.len();
        offset = (offset + 3) & !3;
    }

    for (_, data) in streams {
        w.bytes(data);
        while w.len() % 4 != 0 {
            w.u8(0);
        }
    }

    w.into_vec()
}

fn padded_len(name: &str) -> usize {
    (name.len() + 1 + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_write_parse_roundtrip() {
        let strings = [0u8, b'a', b'b', 0];
        let tables = [2u8; 8];
        let bytes = write_root(
            "v4.0.30319",
            &[("#~", &tables), ("#Strings", &strings), ("#Blob", &[])],
        );
        let root = parse_root(&bytes).expect("parses");
        assert_eq!(root.version, "v4.0.30319");
        assert_eq!(root.streams.len(), 3);
        assert_eq!(root.stream("#Strings").unwrap().size, 4);
        let s = stream_slice(&bytes, root.stream("#Strings").unwrap()).unwrap();
        assert_eq!(s, &strings);
        let t = stream_slice(&bytes, root.stream("#~").unwrap()).unwrap();
        assert_eq!(t, &tables);
    }

    #[test]
    fn bad_signature_is_error() {
        let err = parse_root(b"garbage data!!").expect_err("rejects garbage");
        assert!(matches!(err, Error::BadImage(_)));
    }

    #[test]
    fn out_of_bounds_stream_is_error() {
        let bytes = write_root("v2.0.0", &[("#~", &[1, 2, 3, 4])]);
        let mut evil = bytes.clone();
        evil[28] = 0xFF; // blow up the #~ offset far beyond the root
        let root = parse_root(&evil).unwrap();
        let err = stream_slice(&evil, &root.streams[0]).expect_err("out of bounds");
        assert!(matches!(err, Error::BadImage(_)));
    }
}
