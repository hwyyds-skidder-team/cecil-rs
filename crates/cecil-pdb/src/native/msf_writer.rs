//! Handwritten MSF 7 container emission, including both free-page maps.

use cecil_core::{Error, Result};

const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// Emits stream slots without changing their indices. `None` is absent;
/// `Some(Vec::new())` is an explicitly empty stream.
pub fn write_msf(streams: &[Option<Vec<u8>>], block_size: u32) -> Result<Vec<u8>> {
    if !matches!(block_size, 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768) {
        return Err(Error::argument("unsupported MSF block size"));
    }
    let block = block_size as usize;
    let mut next = 3usize;
    let mut allocate = |count: usize| -> Result<Vec<u32>> {
        let mut pages = Vec::new();
        pages
            .try_reserve(count)
            .map_err(|_| Error::unsupported("cannot allocate MSF block list"))?;
        for _ in 0..count {
            while matches!(next % block, 1 | 2) {
                next = next
                    .checked_add(1)
                    .ok_or_else(|| Error::unsupported("MSF block count overflows"))?;
            }
            pages.push(
                u32::try_from(next)
                    .map_err(|_| Error::unsupported("MSF block count exceeds u32"))?,
            );
            next = next
                .checked_add(1)
                .ok_or_else(|| Error::unsupported("MSF block count overflows"))?;
        }
        Ok(pages)
    };
    let mut page_lists = Vec::with_capacity(streams.len());
    let mut total_stream_pages = 0usize;
    for stream in streams {
        let size = stream.as_ref().map_or(0, Vec::len);
        if size >= u32::MAX as usize {
            return Err(Error::unsupported("MSF stream size exceeds its directory field"));
        }
        let count = size.div_ceil(block);
        total_stream_pages = total_stream_pages
            .checked_add(count)
            .ok_or_else(|| Error::unsupported("MSF directory size overflows"))?;
        page_lists.push(allocate(count)?);
    }
    let directory_size = streams
        .len()
        .checked_add(total_stream_pages)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| Error::unsupported("MSF directory size overflows"))?;
    let directory_word = u32::try_from(directory_size)
        .map_err(|_| Error::unsupported("MSF directory exceeds u32"))?;
    let directory_pages = allocate(directory_size.div_ceil(block))?;
    if directory_pages.len() > block / 4 {
        return Err(Error::unsupported("MSF directory exceeds one standard block-map block"));
    }
    let map = allocate(1)?[0];
    let file_size =
        next.checked_mul(block).ok_or_else(|| Error::unsupported("MSF file size overflows"))?;
    if file_size > u32::MAX as usize {
        return Err(Error::unsupported("MSF output exceeds 4 GiB"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(file_size)
        .map_err(|_| Error::unsupported("cannot allocate MSF output"))?;
    output.resize(file_size, 0);
    output[..32].copy_from_slice(MAGIC);
    put_u32(&mut output, 32, block_size);
    put_u32(&mut output, 36, 1);
    put_u32(&mut output, 40, next as u32);
    put_u32(&mut output, 44, directory_word);
    put_u32(&mut output, 48, 0);
    put_u32(&mut output, 52, map);
    for (stream, pages) in streams.iter().zip(&page_lists) {
        if let Some(bytes) = stream {
            for (chunk, &page) in bytes.chunks(block).zip(pages) {
                let start = page as usize * block;
                output[start..start + chunk.len()].copy_from_slice(chunk);
            }
        }
    }
    let mut directory = Vec::with_capacity(directory_size);
    directory.extend_from_slice(&(streams.len() as u32).to_le_bytes());
    for stream in streams {
        directory
            .extend_from_slice(&stream.as_ref().map_or(u32::MAX, |s| s.len() as u32).to_le_bytes());
    }
    for pages in &page_lists {
        for page in pages {
            directory.extend_from_slice(&page.to_le_bytes());
        }
    }
    for (chunk, &page) in directory.chunks(block).zip(&directory_pages) {
        let start = page as usize * block;
        output[start..start + chunk.len()].copy_from_slice(chunk);
    }
    for (index, page) in directory_pages.iter().enumerate() {
        put_u32(&mut output, map as usize * block + index * 4, *page);
    }
    // Each bitmap page describes block_size * 8 blocks. Its physical slot
    // repeats every block_size blocks; reserve both slots at every interval,
    // including the extra bitmap slots not needed to describe the file yet.
    for interval in 0..next.div_ceil(block) {
        for number in [1usize, 2] {
            let at = (interval * block + number) * block;
            if at >= output.len() {
                continue;
            }
            output[at..at + block].fill(0xff);
            if interval >= next.div_ceil(block * 8) {
                continue;
            }
            let covered = (next - interval * block * 8).min(block * 8);
            for bit in 0..covered {
                output[at + bit / 8] &= !(1 << (bit % 8));
            }
        }
    }
    Ok(output)
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::msf::MsfImage;

    #[test]
    fn emitted_msf_preserves_stream_slots_and_crosses_fpm_boundaries() {
        let streams = vec![None, Some(vec![7; 2_200_000]), Some(Vec::new()), Some(vec![3; 777])];
        let bytes = write_msf(&streams, 512).unwrap();
        let image = MsfImage::parse(&bytes).unwrap();
        assert_eq!(image.stream_count(), 4);
        assert_eq!(image.stream(1), Some(streams[1].as_ref().unwrap().as_slice()));
        assert!(image.stream(0).is_none());
        assert!(image.stream(2).is_none());
        assert_eq!(image.stream(3), Some(streams[3].as_ref().unwrap().as_slice()));
        assert_eq!(bytes[512] & 0b111, 0);
        assert_eq!(bytes[(512 + 1) * 512] & 1, 0);
        // Reserved bitmap blocks that are not needed to cover any file
        // pages must remain entirely free, rather than zero-filled.
        assert!(bytes[1025 * 512..1026 * 512].iter().all(|&byte| byte == 0xff));
    }

    #[test]
    fn invalid_block_size_is_a_structured_error() {
        assert!(write_msf(&[], 128).is_err());
    }
}
