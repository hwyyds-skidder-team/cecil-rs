//! MSF (Multi-Stream File / "Compound File") container parser for native Windows PDBs.
//!
//! Port of the container-level pieces of `Microsoft.Cci.Pdb`:
//!
//! | C# source          | Rust equivalent here                                  |
//! |--------------------|-------------------------------------------------------|
//! | `PdbFileHeader.cs` | [`MsfImage::parse`] header decoding + validation      |
//! | `MsfDirectory.cs`  | directory-stream assembly and per-stream block lists  |
//! | `PdbReader.cs`     | page addressing (`page * page_size + offset`)         |
//! | `DataStream.cs`    | [`MsfStream`] (block chain walked at parse time)      |
//! | `BitAccess.cs`     | explicit little/big-endian integer reads              |
//! | `BitSet.cs`        | [`BitSet`] free-block map decoding                    |
//!
//! The parser is read-only and zero-alloc where possible: a stream that occupies
//! one run of consecutive pages is returned as a borrowed slice of the input;
//! fragmented chains are materialized into a contiguous buffer once, at parse
//! time ([`Cow`] keeps this transparent to callers).
//!
//! Both integer byte orders are supported: standard little-endian files and the
//! rare big-endian variant (same ASCII magic, big-endian integers). The order is
//! detected by validating the decoded page size.

use std::borrow::Cow;

use cecli_core::{Error, Result};

/// Magic shared by every MSF 7.00 image ("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0").
const WINDOWS_PDB_MAGIC: [u8; 32] = *b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// Size of the fixed part of the MSF superblock: magic + 5 `u32` fields.
const HEADER_SIZE: usize = 52;

/// Integer byte order of an MSF image.
///
/// Standard PDBs are little-endian; a small population of historical
/// (PowerPC-era) images uses the same magic with big-endian integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u32_at(self, data: &[u8], off: usize) -> u32 {
        let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        match self {
            ByteOrder::Little => u32::from_le_bytes(b),
            ByteOrder::Big => u32::from_be_bytes(b),
        }
    }
}

/// Decoded MSF superblock (port of `PdbFileHeader`).
#[derive(Debug)]
struct Superblock {
    /// Block/page size in bytes; always a power of two.
    page_size: u32,
    /// Page number of the free-page-map bitmap.
    #[allow(dead_code)]
    free_page_map: u32,
    /// Total number of pages claimed present.
    #[allow(dead_code)]
    pages_used: u32,
    /// Exact byte size of the directory stream.
    directory_size: u32,
    /// Page numbers of the blocks holding the directory's block-index list.
    directory_root: Vec<u32>,
    byte_order: ByteOrder,
}

/// One materialized stream of an MSF image (port of `DataStream`, pre-read).
#[derive(Clone)]
pub struct MsfStream<'a> {
    /// Contiguous stream content: borrowed when the block chain was consecutive,
    /// copied once during [`MsfImage::parse`] otherwise.
    pub data: Cow<'a, [u8]>,
}

impl std::fmt::Debug for MsfStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsfStream")
            .field("len", &self.data.len())
            .field("borrowed", &matches!(self.data, Cow::Borrowed(_)))
            .finish()
    }
}

impl<'a> MsfStream<'a> {
    /// Stream length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Contiguous stream bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// A parsed MSF container over borrowed image bytes.
///
/// Streams are indexed exactly as the directory numbers them (stream 0 in real
/// native PDBs is typically absent and yields [`None`] from [`MsfImage::stream`]).
#[derive(Debug)]
pub struct MsfImage<'a> {
    /// Page size in bytes.
    pub page_size: u32,
    streams: Vec<Option<MsfStream<'a>>>,
}

impl<'a> MsfImage<'a> {
    /// Parses an MSF image from its raw bytes.
    ///
    /// Returns [`Err`] on bad magic, truncated headers/directories, invalid page
    /// sizes or out-of-range block references.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE || data[..32] != WINDOWS_PDB_MAGIC[..] {
            return Err(Error::bad_image(
                "not a native PDB: missing 'Microsoft C/C++ MSF 7.00' MSF magic",
            ));
        }

        // Detect byte order via the page size: it must be a sane power of two.
        let (byte_order, page_size) = match Self::detect_order(data) {
            Some(found) => found,
            None => {
                return Err(Error::bad_image(
                    "invalid MSF page size field (neither endianness decodes to a power of two >= 128)",
                ))
            }
        };

        let sb = Superblock::parse(data, byte_order, page_size)?;
        let directory = Directory::parse(data, &sb)?;

        Ok(MsfImage {
            page_size,
            streams: directory.streams,
        })
    }

    fn detect_order(data: &[u8]) -> Option<(ByteOrder, u32)> {
        for order in [ByteOrder::Little, ByteOrder::Big] {
            let size = order.u32_at(data, 32);
            if !is_valid_page_size(size) {
                continue;
            }
            // Disambiguator: a swapped-order read of the page size can itself
            // be a power of two (e.g. 512 BE reads as 131072 LE), so also
            // require the directory size to be plausible for this image.
            if order.u32_at(data, 44) <= data.len() as u32 {
                return Some((order, size));
            }
        }
        None
    }

    /// Returns the bytes of stream `idx`, or [`None`] when the index is out of
    /// range, the stream was declared with a non-positive size (absent), or its
    /// block list was empty.
    pub fn stream(&self, idx: usize) -> Option<&[u8]> {
        match self.streams.get(idx) {
            Some(Some(s)) => Some(s.as_slice()),
            _ => None,
        }
    }

    /// Number of streams declared by the directory (slots may be absent).
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Iterator over present streams as `(index, bytes)` pairs.
    pub fn streams(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.streams
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|s| (i, s.as_slice())))
    }
}

fn is_valid_page_size(size: u32) -> bool {
    size.is_power_of_two() && size >= 128 && size <= 1 << 20
}

/// `ceil(a / b)` for positive integers.
fn div_ceil_usize(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

impl Superblock {
    fn parse(data: &[u8], byte_order: ByteOrder, page_size: u32) -> Result<Self> {
        let rd = |off: usize| byte_order.u32_at(data, off);

        let superblock = Superblock {
            page_size,
            free_page_map: rd(36),
            pages_used: rd(40),
            directory_size: rd(44),
            // Offset 48 is a reserved zero field in the C# reader; ignored here.
            directory_root: Vec::new(),
            byte_order,
        };

        if superblock.directory_size == 0 {
            return Err(Error::bad_image("MSF directory size is zero"));
        }
        if superblock.directory_size > data.len() as u32 {
            return Err(Error::bad_image(format!(
                "MSF directory size {} exceeds image length {}",
                superblock.directory_size,
                data.len()
            )));
        }

        // PdbFileHeader.cs: number of pages needed to hold the directory's own
        // block-index list ((dirPages * 4) bytes spread over the page size).
        let dir_pages = div_ceil_usize(superblock.directory_size as usize, page_size as usize);
        let root_pages = div_ceil_usize(dir_pages * 4, page_size as usize);
        let root_end = HEADER_SIZE + root_pages * 4;
        if data.len() < root_end {
            return Err(Error::bad_image(format!(
                "truncated MSF header: {} directory-root entries need {} bytes, image has {}",
                root_pages,
                root_end,
                data.len()
            )));
        }

        let mut directory_root = Vec::with_capacity(root_pages);
        for i in 0..root_pages {
            directory_root.push(rd(HEADER_SIZE + i * 4));
        }
        Ok(Superblock { directory_root, ..superblock })
    }
}

/// Free-block bitmap (port of `BitSet`): word count followed by `u32` words.
pub struct BitSet<'b> {
    words: &'b [u8],
    word_count: u32,
    byte_order: ByteOrder,
}

impl<'b> BitSet<'b> {
    /// Decodes a bit set from the front of `data`; returns the set and how many
    /// bytes it consumed (`4 * (word_count + 1)`).
    pub fn from_bytes(data: &'b [u8], byte_order: ByteOrder) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::bad_image("truncated MSF bit set header"));
        }
        let b = [data[0], data[1], data[2], data[3]];
        let word_count = match byte_order {
            ByteOrder::Little => u32::from_le_bytes(b),
            ByteOrder::Big => u32::from_be_bytes(b),
        };
        let consumed = 4usize
            .checked_add(word_count as usize * 4)
            .ok_or_else(|| Error::bad_image("MSF bit set word count overflow"))?;
        if data.len() < consumed {
            return Err(Error::bad_image("truncated MSF bit set words"));
        }
        Ok((
            BitSet {
                words: &data[4..consumed],
                word_count,
                byte_order,
            },
            consumed,
        ))
    }

    /// Whether block `index` is marked set (free).
    pub fn is_set(&self, index: u32) -> bool {
        let word = (index / 32) as usize;
        if word as u32 >= self.word_count {
            return false;
        }
        let off = word * 4;
        let w = match self.byte_order {
            ByteOrder::Little => {
                u32::from_le_bytes(self.words[off..off + 4].try_into().unwrap())
            }
            ByteOrder::Big => u32::from_be_bytes(self.words[off..off + 4].try_into().unwrap()),
        };
        w & (1 << (index % 32)) != 0
    }

    /// True when the set declares no words.
    pub fn is_empty(&self) -> bool {
        self.word_count == 0
    }
}

impl std::fmt::Debug for BitSet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitSet")
            .field("word_count", &self.word_count)
            .finish()
    }
}

/// Directory decoding result: one slot per declared stream.
struct Directory<'a> {
    streams: Vec<Option<MsfStream<'a>>>,
}

impl<'a> Directory<'a> {
    /// Port of `MsfDirectory` + `DataStream.Read`: assemble the directory bytes
    /// from the root-page chain, then walk each stream's block chain.
    fn parse(data: &'a [u8], sb: &Superblock) -> Result<Self> {
        let page_size = sb.page_size as usize;
        let total_pages = data.len() / page_size;
        let dir_bytes = Self::assemble_directory(data, sb, total_pages)?;
        let order = sb.byte_order;
        let rd = |off: usize| order.u32_at(&dir_bytes, off);

        if dir_bytes.len() < 4 {
            return Err(Error::bad_image("truncated MSF directory header"));
        }
        let count = rd(0) as usize;
        if dir_bytes.len() < 4 + count * 4 {
            return Err(Error::bad_image(format!(
                "truncated MSF directory: {} sizes beyond {} bytes",
                count,
                dir_bytes.len()
            )));
        }

        let mut pos = 4 + count * 4;
        let mut streams = Vec::with_capacity(count);
        for i in 0..count {
            // C# treats sizes[i] <= 0 as an absent DataStream.
            let size_signed = rd(4 + i * 4) as i32;
            if size_signed <= 0 {
                streams.push(None);
                continue;
            }
            let size = size_signed as usize;
            let npages = div_ceil_usize(size, page_size);
            if dir_bytes.len() < pos + npages * 4 {
                return Err(Error::bad_image(format!(
                    "truncated MSF directory: block list of stream {i} beyond directory end"
                )));
            }
            let mut pages = Vec::with_capacity(npages);
            for p in 0..npages {
                let page = rd(pos + p * 4);
                if page as usize >= total_pages {
                    return Err(Error::bad_image(format!(
                        "MSF stream {i} references page {} beyond image ({total_pages} pages)",
                        page
                    )));
                }
                pages.push(page as usize);
            }
            pos += npages * 4;
            streams.push(Some(MsfStream {
                data: materialize(data, &pages, page_size, size)?,
            }));
        }

        Ok(Directory { streams })
    }

    /// Gathers the directory stream bytes via MSF's two-level indirection
    /// (`MsfDirectory.cs`): the superblock's root pages hold the block indices
    /// OF the directory itself (that is the `bits.Append(pagesInThisPage * 4)`
    /// loop feeding `new DataStream(directorySize, ...)`); those blocks then
    /// hold the actual directory content, walked exactly like any stream.
    fn assemble_directory(data: &[u8], sb: &Superblock, total_pages: usize) -> Result<Vec<u8>> {
        let page_size = sb.page_size as usize;
        let order = sb.byte_order;
        let indices_per_page = page_size / 4;
        let dir_size = sb.directory_size as usize;

        // Level 1: block indices of the directory content, spread over the
        // root pages listed in the superblock.
        let dir_pages = div_ceil_usize(dir_size, page_size);
        let mut dir_pages_listed = Vec::with_capacity(dir_pages);
        let mut to_go = dir_pages;
        for &root in &sb.directory_root {
            let take = to_go.min(indices_per_page);
            let start = root as usize * page_size;
            let end = start + take * 4;
            if root as usize >= total_pages || end > data.len() {
                return Err(Error::bad_image(format!(
                    "MSF directory root page {root} beyond image ({total_pages} pages)"
                )));
            }
            for w in 0..take {
                dir_pages_listed.push(order.u32_at(data, start + w * 4));
            }
            to_go -= take;
            if to_go == 0 {
                break;
            }
        }
        if to_go > 0 {
            return Err(Error::bad_image(
                "MSF directory root chain ends before covering the directory",
            ));
        }

        // Level 2: concatenate the directory's own blocks.
        let mut out = Vec::with_capacity(dir_size);
        let mut left = dir_size;
        for page in &dir_pages_listed {
            if left == 0 {
                break;
            }
            let todo = left.min(page_size);
            let start = *page as usize * page_size;
            let end = start + todo;
            if *page as usize >= total_pages || end > data.len() {
                return Err(Error::bad_image(format!(
                    "MSF directory block {} beyond image ({total_pages} pages)",
                    page
                )));
            }
            out.extend_from_slice(&data[start..end]);
            left -= todo;
        }
        if left > 0 {
            return Err(Error::bad_image(
                "MSF directory blocks do not cover the declared directory size",
            ));
        }
        Ok(out)
    }
}

/// Walks a block chain and produces the contiguous first `size` bytes.
///
/// Consecutive chains borrow directly from the image; fragmented chains are
/// copied into one buffer (`DataStream.Read` semantics).
fn materialize<'a>(
    data: &'a [u8],
    pages: &[usize],
    page_size: usize,
    size: usize,
) -> Result<Cow<'a, [u8]>> {
    // Fast path: single contiguous run of pages starting at pages[0].
    let consecutive = pages.windows(2).all(|w| w[1] == w[0] + 1);
    if consecutive {
        let start = pages[0] * page_size;
        let end = start + size;
        if end > data.len() {
            return Err(Error::bad_image(format!(
                "MSF stream extends {} bytes past image end",
                end - data.len()
            )));
        }
        return Ok(Cow::Borrowed(&data[start..end]));
    }

    let mut out = Vec::with_capacity(size);
    let mut left = size;
    for &page in pages {
        let todo = left.min(page_size);
        let start = page * page_size;
        let end = start + todo;
        if end > data.len() {
            return Err(Error::bad_image(format!(
                "MSF stream page {page} extends past image end"
            )));
        }
        out.extend_from_slice(&data[start..end]);
        left -= todo;
    }
    debug_assert_eq!(left, 0, "pages list sized from same computation");
    Ok(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 512;

    /// Builds a synthetic little- or big-endian MSF with:
    /// - page 0: superblock (+ directory root entry listing page 5),
    /// - page 1: free-block map marking page 7 free,
    /// - pages 2, 4: stream 1 (1000 bytes, deliberately fragmented),
    /// - page 3:   stream 2 (300 bytes),
    /// - page 5:   directory block-index list (single entry -> page 6),
    /// - page 6:   directory content (28 bytes),
    /// - page 7:   free.
    fn build_msf(be: bool) -> Vec<u8> {
        let put_u32 = |buf: &mut [u8], off: usize, v: u32| {
            let b = if be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            };
            buf[off..off + 4].copy_from_slice(&b);
        };

        let mut img = vec![0u8; 8 * PAGE];
        img[..32].copy_from_slice(&WINDOWS_PDB_MAGIC);

        // Stream contents with distinctive patterns.
        let s1: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let s2: Vec<u8> = (0..300u32).map(|i| (200 + i % 55) as u8).collect();

        // Directory: count=3, sizes=[0,1000,300], then block lists [2,4] and [3].
        let mut dir = Vec::new();
        for v in [3u32, 0, 1000, 300, 2, 4, 3] {
            dir.extend_from_slice(&if be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            });
        }
        assert_eq!(dir.len(), 28);
        img[6 * PAGE..6 * PAGE + dir.len()].copy_from_slice(&dir);
        // Page 5 holds the directory's own block-index list: one entry -> page 6.
        put_u32(&mut img, 5 * PAGE, 6);
        img[2 * PAGE..2 * PAGE + PAGE].copy_from_slice(&s1[..PAGE]);
        img[4 * PAGE..4 * PAGE + s1.len() - PAGE].copy_from_slice(&s1[PAGE..]);
        img[3 * PAGE..3 * PAGE + s2.len()].copy_from_slice(&s2);

        // Header fields.
        put_u32(&mut img, 32, PAGE as u32); // page size
        put_u32(&mut img, 36, 1); // free page map on page 1
        put_u32(&mut img, 40, 7); // pages used
        put_u32(&mut img, 44, dir.len() as u32); // directory size
        put_u32(&mut img, 48, 0); // reserved

        // Directory root: directory fits in one page -> one root entry -> page 5.
        put_u32(&mut img, HEADER_SIZE, 5);

        // Free-block map on page 1: one word header + words marking page 7 free.
        put_u32(&mut img, PAGE, 16);
        put_u32(&mut img, PAGE + 4, 1 << 7);

        img
    }

    #[test]
    fn parses_fragmented_streams_byte_equal() {
        let img = build_msf(false);
        let msf = MsfImage::parse(&img).expect("parses");

        assert_eq!(msf.page_size, 512);
        assert_eq!(msf.stream_count(), 3);
        assert!(msf.stream(0).is_none(), "size-0 stream is absent");

        let s1: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let got1 = msf.stream(1).expect("stream 1");
        assert_eq!(got1, &s1[..]);

        let s2: Vec<u8> = (0..300u32).map(|i| (200 + i % 55) as u8).collect();
        let got2 = msf.stream(2).expect("stream 2");
        assert_eq!(got2, &s2[..]);

        // Fragmented stream was materialized; single-page stream stays borrowed.
        assert!(matches!(msf.streams[1].as_ref().unwrap().data, Cow::Owned(_)));
        assert!(matches!(msf.streams[2].as_ref().unwrap().data, Cow::Borrowed(_)));

        // Out-of-range index yields None rather than panicking.
        assert!(msf.stream(3).is_none());
        assert!(msf.stream(999).is_none());

        let listed: Vec<usize> = msf.streams().map(|(i, _)| i).collect();
        assert_eq!(listed, vec![1, 2]);
    }

    #[test]
    fn parses_big_endian_variant() {
        let img = build_msf(true);
        let msf = MsfImage::parse(&img).expect("big-endian MSF parses");
        assert_eq!(msf.page_size, 512);
        assert_eq!(msf.stream_count(), 3);
        let s2: Vec<u8> = (0..300u32).map(|i| (200 + i % 55) as u8).collect();
        assert_eq!(msf.stream(2), Some(&s2[..]));
    }

    #[test]
    fn corrupt_magic_is_err() {
        let mut img = build_msf(false);
        img[0] = b'X';
        assert!(MsfImage::parse(&img).is_err());

        // Empty and too-short inputs also fail cleanly.
        assert!(MsfImage::parse(&[]).is_err());
        assert!(MsfImage::parse(&img[..10]).is_err());
    }

    #[test]
    fn truncated_directory_is_err() {
        let mut img = build_msf(false);
        // Claim a directory larger than the image.
        let v = 9_000_000u32.to_le_bytes();
        img[44..48].copy_from_slice(&v);
        assert!(MsfImage::parse(&img).is_err());

        // Cut bytes off the end (directory pages 5/6 gone).
        let img = build_msf(false);
        assert!(MsfImage::parse(&img[..6 * PAGE]).is_err());
    }

    #[test]
    fn dangling_block_reference_is_err() {
        let mut img = build_msf(false);
        // Point stream 1's second block at page 42 (past the 8-page image).
        let v = 42u32.to_le_bytes();
        // Directory content sits on page 6: count(4) + 3 sizes(12) + first
        // block index(4) -> second block index of stream 1 at +20.
        let off = 6 * PAGE + 4 + 3 * 4 + 4;
        img[off..off + 4].copy_from_slice(&v);
        assert!(MsfImage::parse(&img).is_err());
    }

    #[test]
    fn invalid_page_size_is_err() {
        let mut img = build_msf(false);
        let v = 500u32.to_le_bytes(); // not a power of two
        img[32..36].copy_from_slice(&v);
        assert!(MsfImage::parse(&img).is_err());
    }

    #[test]
    fn free_block_map_decodes() {
        let img = build_msf(false);
        let (set, used) =
            BitSet::from_bytes(&img[PAGE..PAGE + 256], ByteOrder::Little).expect("bit set");
        assert_eq!(used, 68);
        assert!(!set.is_empty());
        assert!(set.is_set(7));
        assert!(!set.is_set(2));
        assert!(!set.is_set(64), "beyond declared words reads unset");
    }
}
