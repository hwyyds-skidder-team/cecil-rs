//! Read-only views over the metadata heaps: `#Strings`, `#US`, `#GUID`,
//! `#Blob`, and the portable-PDB `#Pdb` heap.
//!
//! All views borrow their payload from the metadata root slice and follow
//! Mono.Cecil semantics for missing or out-of-range indices:
//! - `#Strings` index 0 is the empty string; out-of-range reads yield `""`.
//! - `#Blob` index 0 (or out of range) yields an empty blob.
//! - `#GUID` index 0 (or out of range) yields 16 zero bytes.
//! - `#US` decodes a compressed UTF-16 length whose low bit carries the
//!   "contains special characters" flag byte.

use std::borrow::Cow;

use cecil_core::io::ByteReader;
use cecil_core::token::TableIndex;
use cecil_core::{Error, Result};

/// The `#Strings` heap: NUL-terminated UTF-8 strings, indexed by byte offset.
#[derive(Debug, Clone, Copy)]
pub struct StringHeap<'a> {
    data: &'a [u8],
}

impl<'a> StringHeap<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        StringHeap { data }
    }

    /// Raw heap payload.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the NUL-terminated UTF-8 string at byte offset `index`.
    ///
    /// Index 0 and out-of-range indices return the empty string, matching
    /// Mono.Cecil.
    #[inline]
    pub fn get(&self, index: u32) -> Result<&'a str> {
        if index == 0 {
            return Ok("");
        }
        let start = index as usize;
        if start > self.data.len().saturating_sub(1) {
            return Ok("");
        }
        let end = self.data[start..].iter().position(|&b| b == 0).ok_or_else(|| {
            Error::bad_image(format!("unterminated string at #Strings index {index}"))
        })? + start;
        std::str::from_utf8(&self.data[start..end])
            .map_err(|_| Error::bad_image(format!("invalid UTF-8 at #Strings index {index}")))
    }

    /// Reads a name with replacement characters for invalid UTF-8, ending at
    /// the first NUL or the physical end of the heap. Index 0 and indices
    /// outside the heap yield an empty borrowed string.
    pub fn get_lossy(&self, index: u32) -> Cow<'a, str> {
        if index == 0 {
            return Cow::Borrowed("");
        }
        let Some(tail) = self.data.get(index as usize..) else {
            return Cow::Borrowed("");
        };
        let end = tail.iter().position(|&byte| byte == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end])
    }
}

/// The `#US` user-string heap: compressed-length-prefixed UTF-16 strings with
/// a trailing flag byte.
#[derive(Debug, Clone, Copy)]
pub struct UserStringHeap<'a> {
    data: &'a [u8],
}
impl<'a> UserStringHeap<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        UserStringHeap { data }
    }

    /// Raw heap payload.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Decodes the UTF-16 string at byte offset `index`, honoring the flag
    /// byte encoded in the low bit of the compressed length.
    #[inline]
    pub fn get(&self, index: u32) -> Result<String> {
        let mut r = ByteReader::at(self.data, index as usize);
        let raw = r.compressed_u32()?;
        let length = (raw & !1) as usize;
        if length < 1 {
            return Ok(String::new());
        }
        let bytes = r.read_bytes(length)?;
        if bytes.len() % 2 != 0 {
            return Err(Error::bad_image(format!(
                "odd user-string byte length {length} at #US index {index}"
            )));
        }
        let units = bytes.as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p));
        let mut string = String::with_capacity(bytes.len() / 2);
        for ch in char::decode_utf16(units) {
            string.push(
                ch.map_err(|_| Error::bad_image(format!("invalid UTF-16 at #US index {index}")))?,
            );
        }
        Ok(string)
    }
}

/// The `#Blob` heap: compressed-length-prefixed opaque byte blobs.
#[derive(Debug, Clone, Copy)]
pub struct BlobHeap<'a> {
    data: &'a [u8],
}

impl<'a> BlobHeap<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        BlobHeap { data }
    }

    /// Raw heap payload.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the blob at byte offset `index`. Index 0 and out-of-range
    /// indices return an empty slice, matching Mono.Cecil.
    #[inline]
    pub fn get(&self, index: u32) -> Result<&'a [u8]> {
        if index == 0 || index as usize > self.data.len().saturating_sub(1) {
            return Ok(&[]);
        }
        let mut r = ByteReader::at(self.data, index as usize);
        let length = r.compressed_u32()? as usize;
        let start = r.position();
        if length > self.data.len() - start {
            return Err(Error::bad_image(format!(
                "blob length {length} overruns heap at #Blob index {index}"
            )));
        }
        Ok(&self.data[start..start + length])
    }

    /// Reads only a valid, physically bounded blob. Malformed lengths,
    /// missing prefix bytes and out-of-range indices yield an empty slice.
    pub fn get_tolerant(&self, index: u32) -> &'a [u8] {
        self.get(index).unwrap_or(&[])
    }
}

/// The `#GUID` heap: fixed-size 16-byte GUIDs addressed 1-based.
#[derive(Debug, Clone, Copy)]
pub struct GuidHeap<'a> {
    data: &'a [u8],
}

impl<'a> GuidHeap<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        GuidHeap { data }
    }

    /// Raw heap payload.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the 16-byte GUID with 1-based number `index`. Index 0 and
    /// out-of-range indices return zero bytes, matching Mono.Cecil.
    #[inline]
    pub fn get(&self, index: u32) -> Result<[u8; 16]> {
        const GUID_SIZE: usize = 16;
        // The byte offset is (index-1)*16 — the bound must multiply too,
        // or an index inside `len/16 + 15` passes the check and the slice
        // below panics.
        if index == 0 || index as usize > self.data.len() / GUID_SIZE {
            return Ok([0u8; GUID_SIZE]);
        }
        let mut guid = [0u8; GUID_SIZE];
        let start = (index as usize - 1) * GUID_SIZE;
        guid.copy_from_slice(&self.data[start..start + GUID_SIZE]);
        Ok(guid)
    }
}

/// The portable-PDB `#Pdb` heap: metadata for standalone PDB files.
#[derive(Debug, Clone, Copy)]
pub struct PdbHeap<'a> {
    data: &'a [u8],
    id: &'a [u8],
    entry_point: u32,
    type_system_tables: u64,
    row_counts: [u32; 0x38],
}

impl<'a> PdbHeap<'a> {
    /// Parses a `#Pdb` payload (20-byte id, entry point token, table mask,
    /// per-table row counts).
    pub fn parse(data: &'a [u8]) -> Result<PdbHeap<'a>> {
        let mut r = ByteReader::new(data);
        let id = r.read_bytes(20)?;
        let entry_point = r.u32()?;
        let type_system_tables = r.u64()?;
        if type_system_tables >> 0x38 != 0 {
            return Err(Error::bad_image("#Pdb heap refers to unknown metadata tables"));
        }
        let mut row_counts = [0u32; 0x38];
        for (i, count) in row_counts.iter_mut().enumerate() {
            if type_system_tables & (1u64 << i) != 0 {
                *count = r.u32()?;
            }
        }
        Ok(PdbHeap { data, id, entry_point, type_system_tables, row_counts })
    }

    /// Raw heap payload.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The 20-byte PDB id.
    pub fn id(&self) -> &'a [u8] {
        self.id
    }

    /// Entry point token (`Token::NIL` for DLLs).
    #[inline]
    pub fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Whether the given table has rows recorded in this heap.
    pub fn has_table(&self, table: TableIndex) -> bool {
        self.type_system_tables & (1u64 << (table as u8)) != 0
    }

    /// Row count recorded in the heap for `table` (0 when absent).
    #[inline]
    pub fn row_count(&self, table: TableIndex) -> u32 {
        self.row_counts[table as usize]
    }
}

/// All heaps found in one metadata root. Streams that are absent carry empty
/// payloads.
#[derive(Debug, Clone, Copy)]
pub struct Heaps<'a> {
    /// The `#Strings` heap.
    pub strings: StringHeap<'a>,
    /// The `#US` heap.
    pub user_strings: UserStringHeap<'a>,
    /// The `#Blob` heap.
    pub blob: BlobHeap<'a>,
    /// The `#GUID` heap.
    pub guid: GuidHeap<'a>,
    /// The optional portable-PDB `#Pdb` heap.
    pub pdb: Option<PdbHeap<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_heap_indices_never_panic() {
        for data in [&[][..], &[0][..], &[0, 0, 0, 0][..]] {
            for index in [0, 1, 4, u32::MAX] {
                let _ = StringHeap::new(data).get(index);
                let _ = BlobHeap::new(data).get(index);
                let _ = GuidHeap::new(data).get(index);
                let _ = UserStringHeap::new(data).get(index);
            }
        }
        assert_eq!(GuidHeap::new(&[3; 16]).get(u32::MAX).unwrap(), [0; 16]);
    }

    #[test]
    fn lossy_strings_are_bounded_and_preserve_valid_borrows() {
        let heap = StringHeap::new(b"\0valid\0bad\xff\0tail");
        assert!(matches!(heap.get_lossy(1), std::borrow::Cow::Borrowed("valid")));
        assert_eq!(heap.get_lossy(7), "bad\u{fffd}");
        assert!(heap.get(7).is_err());
        assert_eq!(heap.get_lossy(12), "tail");
        assert!(heap.get(12).is_err());
        for index in [0, 16, u32::MAX] {
            assert_eq!(heap.get_lossy(index), "");
        }
    }

    #[test]
    fn tolerant_blobs_keep_valid_payloads_and_empty_malformed_lengths() {
        let heap = BlobHeap::new(&[0, 2, 1, 2, 0xff]);
        assert_eq!(heap.get_tolerant(1), &[1, 2]);
        assert!(heap.get(4).is_err());
        for index in [0, 4, 5, u32::MAX] {
            assert!(heap.get_tolerant(index).is_empty());
        }
    }

    #[test]
    fn user_strings_decode_unicode_and_reject_unpaired_surrogates() {
        for text in ["", "ascii", "中文", "a😀𝄞é"] {
            let mut bytes = cecil_core::io::ByteWriter::new();
            bytes.compressed_u32(text.encode_utf16().count() as u32 * 2 + 1);
            for unit in text.encode_utf16() {
                bytes.u16(unit);
            }
            bytes.u8(1);
            assert_eq!(UserStringHeap::new(bytes.as_slice()).get(0).unwrap(), text);
        }
        for bytes in [&[3, 0, 0xD8, 1][..], &[3, 0, 0xDC, 1], &[5, 0, 0xD8, 65, 0, 1]] {
            assert!(UserStringHeap::new(bytes).get(0).is_err());
        }
    }
}
