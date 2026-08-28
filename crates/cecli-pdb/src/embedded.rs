//! Embedded Portable PDB wrapper (Roslyn `EmbeddedPortablePdb` format).
//!
//! A portable PDB embedded into its assembly's PE debug directory uses the
//! "MPDB" container: a 4-byte magic, the uncompressed PDB length as a
//! little-endian `u32`, and the PDB bytes compressed with **raw** Deflate
//! (no zlib/gzip header). The wrapper is referenced by an
//! `IMAGE_DEBUG_DIRECTORY` entry of type
//! `image_debug_type::EMBEDDED_PORTABLE_PDB` (Cecil
//! `EmbeddedPortablePdbWriter.GetDebugHeader`, PortablePdb.cs:545-578).

use std::io::{Read, Write};

use cecli_core::{Error, Result};

/// `IMAGE_DEBUG_TYPE` discriminators used by managed images.
pub mod image_debug_type {
    /// CodeView symbol data (`RSDS` payload pointing at a PDB).
    pub const CODEVIEW: i32 = 2;
    /// `/src/sync` determinism marker.
    pub const DETERMINISTIC: i32 = 16;
    /// An embedded portable PDB in the MPDB wrapper.
    pub const EMBEDDED_PORTABLE_PDB: i32 = 17;
    /// PDB content hash (`"<algorithm>\0" + digest`).
    pub const PDB_CHECKSUM: i32 = 19;
}

/// MPDB container magic (`0x4d 0x50 0x44 0x42`).
const MPDB_MAGIC: [u8; 4] = *b"MPDB";

/// Wraps a finished portable PDB into the MPDB container: magic,
/// uncompressed length, raw-Deflate-compressed PDB bytes.
pub fn wrap_embedded(pdb: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(pdb.len() / 2 + 16);
    out.extend_from_slice(&MPDB_MAGIC);
    out.extend_from_slice(&(pdb.len() as u32).to_le_bytes());
    let compressed = {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(pdb)
            .and_then(|_| encoder.finish())
            .map_err(|e| Error::bad_image(format!("embedded pdb deflate failed: {e}")))?
    };
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Unwraps an MPDB container produced by [`wrap_embedded`] (or Roslyn):
/// validates the magic, reads the declared length, inflates the payload,
/// and checks that the decompressed size matches.
pub fn unwrap_embedded(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 8 || payload[..4] != MPDB_MAGIC {
        return Err(Error::bad_image("embedded pdb payload is missing the MPDB magic"));
    }
    let declared = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
    let mut decoder = flate2::read::DeflateDecoder::new(&payload[8..]);
    let mut pdb = Vec::with_capacity(declared);
    decoder
        .read_to_end(&mut pdb)
        .map_err(|e| Error::bad_image(format!("embedded pdb inflate failed: {e}")))?;
    if pdb.len() != declared {
        return Err(Error::bad_image(format!(
            "embedded pdb size mismatch: header says {declared}, inflated {}",
            pdb.len()
        )));
    }
    Ok(pdb)
}

/// SHA-256 digest of `data` (the `PdbChecksum` debug-entry payload body).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Builds the `PdbChecksum` debug-entry payload: `"SHA256"\0` + digest.
pub fn pdb_checksum_payload(pdb: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(7 + 32);
    payload.extend_from_slice(b"SHA256\0");
    payload.extend_from_slice(&sha256(pdb));
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrips() {
        let pdb = vec![0x42u8; 1000]; // compressible
        let wrapped = wrap_embedded(&pdb).expect("wrap");
        assert_eq!(&wrapped[..4], b"MPDB");
        assert_eq!(u32::from_le_bytes(wrapped[4..8].try_into().unwrap()), 1000);
        assert!(wrapped.len() < pdb.len(), "payload compresses");
        let back = unwrap_embedded(&wrapped).expect("unwrap");
        assert_eq!(back, pdb);
    }

    #[test]
    fn unwrap_rejects_bad_magic_and_size() {
        assert!(unwrap_embedded(b"nope").is_err());
        assert!(unwrap_embedded(&[]).is_err());
        // Declared size lying about the content.
        let mut lying = Vec::new();
        lying.extend_from_slice(b"MPDB");
        lying.extend_from_slice(&999u32.to_le_bytes());
        lying.extend_from_slice(&[0x78]); // not valid raw deflate of 999 bytes
        assert!(unwrap_embedded(&lying).is_err());
    }

    #[test]
    fn checksum_payload_shape() {
        let payload = pdb_checksum_payload(b"abc");
        assert_eq!(&payload[..7], b"SHA256\0");
        assert_eq!(payload.len(), 7 + 32);
    }
}
