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

use cecli_core::io::ByteReader;
use cecli_core::token::TableIndex;
use cecli_core::{Error, Result};

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
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the NUL-terminated UTF-8 string at byte offset `index`.
    ///
    /// Index 0 and out-of-range indices return the empty string, matching
    /// Mono.Cecil.
    pub fn get(&self, index: u32) -> Result<&'a str> {
        if index == 0 {
            return Ok("");
        }
        let start = index as usize;
        if start > self.data.len().saturating_sub(1) {
            return Ok("");
        }
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::bad_image(format!("unterminated string at #Strings index {index}")))?
            + start;
        std::str::from_utf8(&self.data[start..end])
            .map_err(|_| Error::bad_image(format!("invalid UTF-8 at #Strings index {index}")))
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
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Decodes the UTF-16 string at byte offset `index`, honoring the flag
    /// byte encoded in the low bit of the compressed length.
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
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| Error::bad_image(format!("invalid UTF-16 at #US index {index}")))
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
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the blob at byte offset `index`. Index 0 and out-of-range
    /// indices return an empty slice, matching Mono.Cecil.
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
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the 16-byte GUID with 1-based number `index`. Index 0 and
    /// out-of-range indices return zero bytes, matching Mono.Cecil.
    pub fn get(&self, index: u32) -> Result<[u8; 16]> {
        const GUID_SIZE: usize = 16;
        if index == 0 || ((index as usize - 1) + GUID_SIZE) > self.data.len() {
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
        let mut row_counts = [0u32; 0x38];
        for i in 0..0x38 {
            if type_system_tables & (1u64 << i) != 0 {
                row_counts[i] = r.u32()?;
            }
        }
        Ok(PdbHeap {
            data,
            id,
            entry_point,
            type_system_tables,
            row_counts,
        })
    }

    /// Raw heap payload.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The 20-byte PDB id.
    pub fn id(&self) -> &'a [u8] {
        self.id
    }

    /// Entry point token (`Token::NIL` for DLLs).
    pub fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Whether the given table has rows recorded in this heap.
    pub fn has_table(&self, table: TableIndex) -> bool {
        self.type_system_tables & (1u64 << (table as u8)) != 0
    }

    /// Row count recorded in the heap for `table` (0 when absent).
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
