#![cfg(feature = "strongname")]
//! Strong-name key handling and assembly signing.
//!
//! Rust port of:
//! - `Mono.Security.Cryptography/CryptoConvert.cs` — CAPI (`RSA1`/`RSA2`)
//!   blob parsing and serialization,
//! - `Mono.Security.Cryptography/CryptoService.cs` — the ECMA public-key
//!   layout and the strong-name signing pipeline,
//! - the strong-name step of `Mono.Cecil/AssemblyWriter.cs` (the
//!   `CryptoService.StrongName` call right after image writing).
//!
//! The signing layout follows Cecil/IKVM exactly: locate the CLI header's
//! strong-name signature directory, zero it, recompute the PE checksum over
//! the zeroed content (Cecil's `ImageWriter` patches the checksum before
//! `CryptoService` hashes, and the signature write lands in the same slot),
//! hash the PE over `[0..header_size) ∪ [text_raw_start..sn_start) ∪
//! [sn_end..eof)` with SHA-1 (or SHA-256 when selected), RSA-sign the digest
//! with PKCS#1 v1.5, and write the big-endian signature back into the
//! directory slot.

use std::fmt;

use sha2::Digest;

/// CALG_RSA_SIGN (`ALG_ID` used by `sn.exe`-generated keys).
pub const CALG_RSA_SIGN: u32 = 0x0000_2400;
/// CALG_SHA1.
pub const CALG_SHA1: u32 = 0x0000_8004;
/// CALG_SHA_256.
pub const CALG_SHA_256: u32 = 0x0000_800c;

/// Digest algorithms usable for strong-name signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureHashAlgorithm {
    /// SHA-1 (Cecil's default).
    Sha1,
    /// SHA-256.
    Sha256,
}

/// Error raised while parsing key blobs or signing images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrongNameError {
    pub message: String,
}

impl StrongNameError {
    fn new(message: impl Into<String>) -> Self {
        StrongNameError { message: message.into() }
    }
}

impl fmt::Display for StrongNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StrongNameError {}

pub type Result<T, E = StrongNameError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// SHA-1
//
// `sha2` only provides the SHA-2 family, and pulling another dependency for
// one legacy algorithm is not worth it, so SHA-1 lives here (FIPS 180-1).
// ---------------------------------------------------------------------------

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let tmp =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// CryptoConvert port — CAPI key blob (de)serialization.
//
// Blob layouts (integers stored little-endian on disk):
//
// PUBLICKEYBLOB (RSA1):               PRIVATEKEYBLOB (RSA2):
//   0: bType = 0x06                     0: bType = 0x07
//   1: bVersion = 0x02                  1: bVersion = 0x02
//   2..4: reserved                      2..4: reserved
//   4..8: aiKeyAlg                      4..8: aiKeyAlg
//   8..12: magic "RSA1"                 8..12: magic "RSA2" (0x32415352)
//   12..16: bitlen                      12..16: bitlen
//   16..20: pubexp DWORD                16..20: pubexp DWORD
//   20..: modulus                       20..: modulus, prime1, prime2,
//                                             exponent1, exponent2,
//                                             coefficient, privateExponent
// ---------------------------------------------------------------------------

/// RSA key material decoded from a CAPI blob; every component is stored
/// big-endian (as required by `BigUint::from_bytes_be`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapiKey {
    /// `aiKeyAlg` from the blob header.
    pub alg_id: u32,
    /// Key size in bits.
    pub bit_len: u32,
    /// Public modulus (big-endian).
    pub modulus: Vec<u8>,
    /// Public exponent (big-endian, minimal length).
    pub exponent: Vec<u8>,
    /// Private exponent (big-endian). Absent when the blob stops after the
    /// coefficient field — CryptoAPI tolerates that because it computes with
    /// the CRT parameters by default (see the bug note in `CryptoConvert`).
    pub d: Option<Vec<u8>>,
    pub prime1: Option<Vec<u8>>,
    pub prime2: Option<Vec<u8>>,
    pub exponent1: Option<Vec<u8>>,
    pub exponent2: Option<Vec<u8>>,
    pub coefficient: Option<Vec<u8>>,
    /// True when the source blob was wrapped in an extra 12-byte ECMA header
    /// (the `AssemblyName.PublicKey` / `sn -e` layout).
    pub headered: bool,
}

impl CapiKey {
    /// True when the blob carries private-key material.
    pub fn is_private(&self) -> bool {
        self.prime1.is_some()
    }

    /// True when the source blob had an ECMA header wrapper.
    pub fn is_headered(&self) -> bool {
        self.headered
    }
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(StrongNameError::new("invalid blob: truncated header"));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(StrongNameError::new("invalid blob: truncated header"));
    }
    Ok(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    if offset.checked_add(len).map(|end| end > data.len()) != Some(false) {
        return Err(StrongNameError::new("invalid blob: truncated body"));
    }
    Ok(&data[offset..offset + len])
}

/// Reverses `bytes` into a fresh buffer (CAPI stores multi-byte integers
/// little-endian; RSA math wants big-endian).
fn to_be(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.reverse();
    out
}

/// Right-aligns a big-endian component into a little-endian field of
/// `len` bytes (`pad_le` semantics shared with the tests).
fn le_field(be: &[u8], len: usize) -> Vec<u8> {
    debug_assert!(be.len() <= len, "component wider than its field");
    let mut out = vec![0u8; len];
    let copy_len = be.len().min(len);
    out[len - copy_len..].copy_from_slice(&be[be.len() - copy_len..]);
    out.reverse();
    out
}

fn from_capi_private_blob(data: &[u8], offset: usize) -> Result<CapiKey> {
    if slice_at(data, offset, 20).is_err()
        || data[offset] != 0x07
        || data[offset + 1] != 0x02
        || data[offset + 2] != 0x00
        || data[offset + 3] != 0x00
        || u32_at(data, offset + 8)? != 0x3241_5352
    {
        return Err(StrongNameError::new("Invalid blob header"));
    }

    // ALGID (CALG_RSA_SIGN, CALG_RSA_KEYX, ...).
    let alg_id = u32_at(data, offset + 4)?;
    // DWORD bitlen.
    let bit_len = u32_at(data, offset + 12)?;

    // DWORD public exponent; trim leading zeros of the big-endian form.
    let mut exponent = to_be(slice_at(data, offset + 16, 4)?);
    while exponent.len() > 1 && exponent[0] == 0 {
        exponent.remove(0);
    }

    let byte_len = (bit_len >> 3) as usize;
    let half_len = byte_len / 2;
    let mut pos = offset + 20;

    let modulus = to_be(slice_at(data, pos, byte_len)?);
    pos += byte_len;
    let prime1 = to_be(slice_at(data, pos, half_len)?);
    pos += half_len;
    let prime2 = to_be(slice_at(data, pos, half_len)?);
    pos += half_len;
    let exponent1 = to_be(slice_at(data, pos, half_len)?);
    pos += half_len;
    let exponent2 = to_be(slice_at(data, pos, half_len)?);
    pos += half_len;
    let coefficient = to_be(slice_at(data, pos, half_len)?);
    pos += half_len;

    // CryptoAPI hack (see CryptoConvert.cs): the private-exponent field may
    // be omitted entirely; the CRT parameters suffice for signing.
    let d = if byte_len > 0 && pos + byte_len <= data.len() {
        Some(to_be(slice_at(data, pos, byte_len)?))
    } else {
        None
    };

    Ok(CapiKey {
        alg_id,
        bit_len,
        modulus,
        exponent,
        d,
        prime1: Some(prime1),
        prime2: Some(prime2),
        exponent1: Some(exponent1),
        exponent2: Some(exponent2),
        coefficient: Some(coefficient),
        headered: false,
    })
}

fn from_capi_public_blob(data: &[u8], offset: usize) -> Result<CapiKey> {
    if slice_at(data, offset, 20).is_err()
        || data[offset] != 0x06
        || data[offset + 1] != 0x02
        || data[offset + 2] != 0x00
        || data[offset + 3] != 0x00
        || u32_at(data, offset + 8)? != 0x3141_5352
    {
        return Err(StrongNameError::new("Invalid blob header"));
    }

    // ALGID (CALG_RSA_SIGN, CALG_RSA_KEYX, ...).
    let alg_id = u32_at(data, offset + 4)?;
    // DWORD bitlen.
    let bit_len = u32_at(data, offset + 12)?;

    // DWORD public exponent; CryptoConvert keeps exactly three big-endian
    // bytes ([18], [17], [16]).
    let exponent = vec![data[offset + 18], data[offset + 17], data[offset + 16]];

    let byte_len = (bit_len >> 3) as usize;
    let modulus = to_be(slice_at(data, offset + 20, byte_len)?);

    Ok(CapiKey {
        alg_id,
        bit_len,
        modulus,
        exponent,
        d: None,
        prime1: None,
        prime2: None,
        exponent1: None,
        exponent2: None,
        coefficient: None,
        headered: false,
    })
}

/// Port of `CryptoConvert.FromCapiKeyBlob`: dispatches on the blob type byte,
/// transparently unwrapping the 12-byte ECMA header some tools emit.
pub fn from_capi_key_blob(blob: &[u8]) -> Result<CapiKey> {
    if blob.is_empty() {
        return Err(StrongNameError::new("blob is too small."));
    }
    let mut key = match blob[0] {
        // This could be a public key behind a header, like "sn -e" produces.
        0x00 if blob.len() > 12 && blob[12] == 0x06 => from_capi_public_blob(blob, 12)?,
        0x06 => from_capi_public_blob(blob, 0)?,
        0x07 => from_capi_private_blob(blob, 0)?,
        _ => return Err(StrongNameError::new("Unknown blob format.")),
    };
    key.headered = blob[0] == 0x00;
    Ok(key)
}

/// Port of `CryptoConvert.ToCapiPublicKeyBlob`: serializes `(n, e)` into a
/// CAPI `PUBLICKEYBLOB` (`RSA1`). Components are big-endian inputs.
pub fn to_capi_public_blob(modulus_be: &[u8], exponent_be: &[u8]) -> Vec<u8> {
    let key_length = modulus_be.len();
    let mut blob = vec![0u8; 20 + key_length];

    blob[0] = 0x06; // Type - PUBLICKEYBLOB
    blob[1] = 0x02; // Version - CUR_BLOB_VERSION
                    // blob[2..4] stays zero (reserved).
    blob[5] = 0x24; // ALGID - CALG_RSA_SIGN
    blob[8] = b'R'; // Magic "RSA1"
    blob[9] = b'S';
    blob[10] = b'A';
    blob[11] = b'1';

    blob[12..16].copy_from_slice(&((key_length as u32) << 3).to_le_bytes());

    // Public exponent, right-aligned little-endian DWORD.
    let mut pos = 16;
    for &byte in exponent_be.iter().rev().take(4) {
        blob[pos] = byte;
        pos += 1;
    }

    // Modulus, little-endian (reversed big-endian).
    blob[20..20 + key_length].copy_from_slice(&to_be(modulus_be));
    blob
}

/// Serializes a parsed private key into a CAPI `PRIVATEKEYBLOB` (`RSA2`) —
/// the inverse of [`from_capi_private_blob`] and the shape of a private
/// `.snk`. CRT fields missing from `key` are recomputed from `(p, q, d)`.
pub fn to_capi_private_blob(key: &CapiKey) -> Result<Vec<u8>> {
    use rsa::BigUint;

    let p_be =
        key.prime1.as_deref().ok_or_else(|| StrongNameError::new("key lacks private material"))?;
    let q_be =
        key.prime2.as_deref().ok_or_else(|| StrongNameError::new("key lacks private material"))?;
    let d_be = key
        .d
        .as_deref()
        .filter(|d| d.iter().any(|&b| b != 0))
        .ok_or_else(|| StrongNameError::new("key lacks a private exponent"))?;

    let byte_len = key.modulus.len();
    let half_len = byte_len / 2;

    // Derive any missing CRT components (qinv via Fermat: q^(p-2) mod p).
    let exponent1 = match &key.exponent1 {
        Some(x) => x.clone(),
        None => {
            let p = BigUint::from_bytes_be(p_be);
            let d = BigUint::from_bytes_be(d_be);
            pad_to_be(d % (p.clone() - 1u32), half_len)
        }
    };
    let exponent2 = match &key.exponent2 {
        Some(x) => x.clone(),
        None => {
            let q = BigUint::from_bytes_be(q_be);
            let d = BigUint::from_bytes_be(d_be);
            pad_to_be(d % (q.clone() - 1u32), half_len)
        }
    };
    let coefficient = match &key.coefficient {
        Some(x) => x.clone(),
        None => {
            let p = BigUint::from_bytes_be(p_be);
            let q = BigUint::from_bytes_be(q_be);
            pad_to_be(q.modpow(&(p.clone() - 2u32), &p), half_len)
        }
    };

    let mut blob = Vec::with_capacity(20 + 2 * byte_len + 5 * half_len);
    blob.push(0x07); // PRIVATEKEYBLOB
    blob.push(0x02); // version
    blob.extend_from_slice(&[0, 0]); // reserved
    blob.extend_from_slice(&key.alg_id.to_le_bytes());
    blob.extend_from_slice(b"RSA2"); // DWORD magic = 0x32415352
    blob.extend_from_slice(&key.bit_len.to_le_bytes());
    blob.extend_from_slice(&le_field(&key.exponent, 4)); // pubexp DWORD
    blob.extend_from_slice(&to_be(&key.modulus));
    blob.extend_from_slice(&le_field(p_be, half_len));
    blob.extend_from_slice(&le_field(q_be, half_len));
    blob.extend_from_slice(&le_field(&exponent1, half_len));
    blob.extend_from_slice(&le_field(&exponent2, half_len));
    blob.extend_from_slice(&le_field(&coefficient, half_len));
    blob.extend_from_slice(&le_field(d_be, byte_len));
    debug_assert_eq!(blob.len(), 20 + 2 * byte_len + 5 * half_len);
    Ok(blob)
}

// ---------------------------------------------------------------------------
// CryptoService.GetPublicKey port — ECMA public-key layout
// ---------------------------------------------------------------------------

/// Builds the ECMA key blob stored in `AssemblyName.PublicKey` /
/// `AssemblyReference.PublicKey`: a 12-byte header followed by the CAPI
/// public-key blob.
///
/// Header layout: `[0..4]` signature ALG_ID = `CALG_RSA_SIGN`, `[4..8]` hash
/// ALG_ID = `CALG_SHA1`, `[8..12]` length of the following CAPI blob.
pub fn ecma_public_key(modulus_be: &[u8], exponent_be: &[u8]) -> Vec<u8> {
    let csp_blob = to_capi_public_blob(modulus_be, exponent_be);
    let mut public_key = vec![0u8; 12 + csp_blob.len()];
    public_key[12..].copy_from_slice(&csp_blob);
    public_key[1] = 36; // ALG_ID - Signature: CALG_RSA_SIGN
    public_key[4] = 4; // ALG_ID - Hash: CALG_SHA1
    public_key[5] = 128;
    let len = csp_blob.len() as u32;
    public_key[8..12].copy_from_slice(&len.to_le_bytes());
    public_key
}

// ---------------------------------------------------------------------------
// PKCS#1 v1.5 signatures over raw RSA primitives
// ---------------------------------------------------------------------------

/// DER `DigestInfo` prefix for SHA-1.
const DIGEST_INFO_SHA1: &[u8] =
    &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];

/// DER `DigestInfo` prefix for SHA-256.
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn digest_info_prefix(alg: SignatureHashAlgorithm) -> &'static [u8] {
    match alg {
        SignatureHashAlgorithm::Sha1 => DIGEST_INFO_SHA1,
        SignatureHashAlgorithm::Sha256 => DIGEST_INFO_SHA256,
    }
}

/// EMSA-PKCS1-v1_5 encoding followed by the raw RSA private-key operation
/// ($m^d \bmod n$). Returns the big-endian signature, `k` bytes wide — the
/// same bytes .NET's `RSAPKCS1SignatureFormatter` produces once Cecil's
/// `Array.Reverse` has been applied.
fn pkcs1_v15_sign(
    n: &rsa::BigUint,
    d: &rsa::BigUint,
    alg: SignatureHashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let prefix = digest_info_prefix(alg);
    let k = ((n.bits() + 7) / 8) as usize;
    let t_len = prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err(StrongNameError::new("RSA modulus too small for signature"));
    }

    let mut em = vec![0u8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    for byte in em[2..k - t_len - 1].iter_mut() {
        *byte = 0xff;
    }
    em[k - t_len - 1] = 0x00;
    em[k - t_len..k - digest.len()].copy_from_slice(prefix);
    em[k - digest.len()..].copy_from_slice(digest);

    let m = rsa::BigUint::from_bytes_be(&em);
    let signature = m.modpow(d, n);
    Ok(pad_to_be(signature, k))
}

/// Verifies a PKCS#1 v1.5 signature against a digest: recovers $s^e \bmod n$
/// and compares the encoded block.
#[cfg(test)]
fn pkcs1_v15_verify(
    n: &rsa::BigUint,
    e: &rsa::BigUint,
    alg: SignatureHashAlgorithm,
    digest: &[u8],
    signature_be: &[u8],
) -> bool {
    let prefix = digest_info_prefix(alg);
    let k = ((n.bits() + 7) / 8) as usize;
    if signature_be.len() != k {
        return false;
    }
    let s = rsa::BigUint::from_bytes_be(signature_be);
    let em = pad_to_be(s.modpow(e, n), k);
    let t_len = prefix.len() + digest.len();
    em[0] == 0x00
        && em[1] == 0x01
        && em[2..k - t_len - 1].iter().all(|&b| b == 0xff)
        && em[k - t_len - 1] == 0x00
        && &em[k - t_len..k - digest.len()] == prefix
        && &em[k - digest.len()..] == digest
}

fn pad_to_be(value: rsa::BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= len {
        return bytes;
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

// ---------------------------------------------------------------------------
// PE layout scanning (port of CryptoService.HashStream's addressing)
// ---------------------------------------------------------------------------

/// File-offset facts about a PE image needed to hash around the strong-name
/// signature directory.
#[derive(Debug, Clone, Copy)]
struct PeLayout {
    /// Size of DOS + PE + COFF headers + optional header + section table.
    header_size: usize,
    /// First (text) section `PointerToRawData`.
    text_pointer: usize,
    /// File offset of the strong-name signature directory contents.
    sn_pointer: usize,
    /// Size of the strong-name signature directory.
    sn_size: usize,
    /// File offset of the `CheckSum` field in the optional header.
    checksum_offset: usize,
}

fn pe_layout(data: &[u8]) -> Result<PeLayout> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(StrongNameError::new("not a PE image: missing MZ header"));
    }
    let pe_offset = u32_at(data, 0x3c)? as usize;
    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(StrongNameError::new("not a PE image: missing PE signature"));
    }

    let coff = pe_offset + 4;
    let sections = u16_at(data, coff + 2)? as usize;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let opt = coff + 20;

    let magic = u16_at(data, opt)?;
    let (num_dirs_offset, dd_offset) = match magic {
        0x10b => (opt + 92, opt + 96),
        0x20b => (opt + 108, opt + 112),
        _ => {
            return Err(StrongNameError::new(format!(
                "unknown PE optional-header magic {magic:#x}"
            )))
        }
    };
    if u16_at(data, num_dirs_offset)? < 15 {
        return Err(StrongNameError::new("image has no CLI data directory"));
    }
    let cli_rva = u32_at(data, dd_offset + 14 * 8)?;
    let cli_size = u32_at(data, dd_offset + 14 * 8 + 4)?;
    if cli_rva == 0 || cli_size == 0 {
        return Err(StrongNameError::new("image has no CLI header directory"));
    }

    let section_table = opt + opt_size;
    if section_table + 40 * sections > data.len() {
        return Err(StrongNameError::new("section table extends past end of file"));
    }
    // Section header: Name(0..8) VirtualSize(8) VirtualAddress(12)
    // SizeOfRawData(16) PointerToRawData(20).
    let text_va = u32_at(data, section_table + 12)?;
    let text_pointer = u32_at(data, section_table + 20)? as usize;
    let header_size = section_table + 40 * sections;
    if text_pointer >= data.len() {
        return Err(StrongNameError::new("text section starts past end of file"));
    }

    // RVA → file offset through the first section, exactly like Cecil's
    // `text_section_pointer + (directory.VirtualAddress - text.VirtualAddress)`.
    let rva_offset = |rva: u32| -> Result<usize> {
        if rva < text_va {
            return Err(StrongNameError::new("directory RVA precedes the text section"));
        }
        let offset = text_pointer + (rva - text_va) as usize;
        if offset >= data.len() {
            return Err(StrongNameError::new("directory RVA maps past end of file"));
        }
        Ok(offset)
    };

    let cli_offset = rva_offset(cli_rva)?;
    // COR20 header: cb(0) runtime(4) metadata(8) flags(16) entrypoint(20)
    // resources(24) strongname(32).
    let sn_rva = u32_at(data, cli_offset + 32)?;
    let sn_size = u32_at(data, cli_offset + 36)? as usize;
    if sn_rva == 0 || sn_size == 0 {
        return Err(StrongNameError::new("image has no strong-name signature directory"));
    }
    let sn_pointer = rva_offset(sn_rva)?;
    if sn_pointer + sn_size > data.len() {
        return Err(StrongNameError::new("strong-name signature extends past end of file"));
    }

    Ok(PeLayout { header_size, text_pointer, sn_pointer, sn_size, checksum_offset: opt + 64 })
}

/// Recomputes and patches the PE `CheckSum` field (the field itself is
/// treated as zero while summing): 16-bit fold-with-carry over every word,
/// folded once more, plus the file length.
fn patch_pe_checksum(data: &mut [u8], checksum_offset: usize) {
    data[checksum_offset..checksum_offset + 4].fill(0);

    let mut sum: u32 = 0;
    for chunk in data.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if data.len() % 2 == 1 {
        sum += *data.last().unwrap() as u32;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = sum.wrapping_add(data.len() as u32);

    data[checksum_offset..checksum_offset + 4].copy_from_slice(&sum.to_le_bytes());
}

/// Port of `CryptoService.HashStream`: hashes the image with the strong-name
/// directory skipped (it must already be zeroed), covering `[0..header_size)`,
/// `[text_raw_start..sn_start)` and `[sn_end..eof)`. The gap between the
/// header table and the text section's raw data is intentionally not hashed,
/// matching Cecil byte-for-byte.
fn hash_image(data: &[u8], layout: &PeLayout, alg: SignatureHashAlgorithm) -> Result<Vec<u8>> {
    let regions = [
        &data[..layout.header_size],
        &data[layout.text_pointer..layout.sn_pointer],
        &data[layout.sn_pointer + layout.sn_size..],
    ];
    match alg {
        SignatureHashAlgorithm::Sha1 => {
            let total: usize = regions.iter().map(|r| r.len()).sum();
            let mut buf = Vec::with_capacity(total);
            for region in regions {
                buf.extend_from_slice(region);
            }
            Ok(sha1_digest(&buf).to_vec())
        }
        SignatureHashAlgorithm::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            for region in regions {
                hasher.update(region);
            }
            Ok(hasher.finalize().to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// StrongNameKeyPair
// ---------------------------------------------------------------------------

/// A strong-name key pair loaded from a `.snk` file — either a full RSA
/// private key (`RSA2`) or a public-key-only blob (`RSA1`).
///
/// Rust counterpart of the `System.Reflection.StrongNameKeyPair` surface
/// Cecil drives through `WriterParameters`, backed by the `CryptoConvert`
/// port above.
#[derive(Debug, Clone)]
pub struct StrongNameKeyPair {
    bytes: Vec<u8>,
}

impl StrongNameKeyPair {
    /// Creates a key pair from raw `.snk` contents. Accepts `RSA1` public
    /// blobs, `RSA2` private blobs and ECMA-headered variants. The blob is
    /// validated up front; signing fails later for public-only keys.
    pub fn new(snk: &[u8]) -> Result<Self> {
        from_capi_key_blob(snk)?;
        Ok(StrongNameKeyPair { bytes: snk.to_vec() })
    }

    /// The original `.snk` bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// True when the blob carries no private key material.
    pub fn is_public_only(&self) -> bool {
        !from_capi_key_blob(&self.bytes).map(|key| key.is_private()).unwrap_or(false)
    }

    /// The hash algorithm implied by the blob's `ALG_ID`: SHA-1 unless the
    /// key advertises SHA-256 (Cecil always signs with SHA-1; use
    /// [`Self::sign_image_with`] to force SHA-256).
    pub fn hash_algorithm(&self) -> SignatureHashAlgorithm {
        match from_capi_key_blob(&self.bytes) {
            Ok(key) if key.alg_id == CALG_SHA_256 => SignatureHashAlgorithm::Sha256,
            _ => SignatureHashAlgorithm::Sha1,
        }
    }

    /// The ECMA-format public key (`AssemblyName.PublicKey` shape: 12-byte
    /// header + CAPI `PUBLICKEYBLOB`).
    ///
    /// A public-key-only `.snk` is passed through unchanged — it already is
    /// exactly that blob. A private `.snk` derives its public part
    /// (`CryptoService.GetPublicKey` port).
    pub fn public_key(&self) -> Vec<u8> {
        match from_capi_key_blob(&self.bytes) {
            // Already a public blob (bare RSA1 or ECMA-headered): passthrough.
            Ok(key) if !key.is_private() => self.bytes.clone(),
            // Private key: rebuild the public part like CryptoService does.
            Ok(key) => ecma_public_key(&key.modulus, &key.exponent),
            // Unreachable: `new` validates the blob.
            Err(_) => Vec::new(),
        }
    }

    /// Signs a finished PE/CLI image in place — port of
    /// `CryptoService.StrongName`. Uses the hash algorithm implied by the
    /// key blob (see [`Self::hash_algorithm`]).
    ///
    /// The caller hands over the exact bytes written to disk (Cecil calls
    /// this right after `ImageWriter.WriteImage` on the output stream).
    pub fn sign_image(&self, image: &mut Vec<u8>) -> Result<()> {
        self.sign_image_with(image, self.hash_algorithm())
    }

    /// [`Self::sign_image`] with an explicit digest algorithm (SHA-256 is
    /// what modern toolchains use even for SHA-1-era keys).
    pub fn sign_image_with(&self, image: &mut Vec<u8>, alg: SignatureHashAlgorithm) -> Result<()> {
        let key = from_capi_key_blob(&self.bytes)?;
        if !key.is_private() {
            return Err(StrongNameError::new("cannot sign with a public-only strong-name key"));
        }
        let (n, d) = private_key_parts(&key)?;

        // Zero the signature slot, then make sure the checksum matches the
        // pre-signature content — Cecil patches the checksum while writing
        // the image and only splices the signature in afterwards, so the
        // shipped checksum never covers the signature itself.
        let layout = pe_layout(image)?;
        for byte in &mut image[layout.sn_pointer..layout.sn_pointer + layout.sn_size] {
            *byte = 0;
        }
        patch_pe_checksum(image, layout.checksum_offset);

        // Hash everything except the signature directory…
        let digest = hash_image(image, &layout, alg)?;

        // …and the signature must fit back into the directory slot.
        if layout.sn_size < ((n.bits() + 7) / 8) as usize {
            return Err(StrongNameError::new(
                "strong-name signature directory is smaller than the RSA signature",
            ));
        }
        let signature = pkcs1_v15_sign(&n, &d, alg, &digest)?;
        image[layout.sn_pointer..layout.sn_pointer + signature.len()].copy_from_slice(&signature);
        Ok(())
    }
}

/// Materializes `(n, d)` from a parsed private blob. When the blob omitted
/// the private exponent (a CryptoAPI quirk `CryptoConvert` documents), `d`
/// is rebuilt from the CRT parameters via `rsa::RsaPrivateKey::from_p_q`.
/// Blobs that do carry `d` are validated through `rsa` so malformed keys
/// surface as errors instead of garbage signatures.
fn private_key_parts(key: &CapiKey) -> Result<(rsa::BigUint, rsa::BigUint)> {
    use rsa::traits::PrivateKeyParts;

    let n = rsa::BigUint::from_bytes_be(&key.modulus);
    let p = key
        .prime1
        .as_ref()
        .map(|p| rsa::BigUint::from_bytes_be(p))
        .ok_or_else(|| StrongNameError::new("invalid blob: no private key material"))?;
    let q = key
        .prime2
        .as_ref()
        .map(|q| rsa::BigUint::from_bytes_be(q))
        .ok_or_else(|| StrongNameError::new("invalid blob: no private key material"))?;
    let e = rsa::BigUint::from_bytes_be(&key.exponent);

    let d_value = match &key.d {
        Some(d) if d.iter().any(|&b| b != 0) => rsa::BigUint::from_bytes_be(d),
        _ => {
            let rebuilt = rsa::RsaPrivateKey::from_p_q(p, q, e)
                .map_err(|err| StrongNameError::new(format!("invalid private key: {err}")))?;
            return Ok((n, rebuilt.d().clone()));
        }
    };

    rsa::RsaPrivateKey::from_components(n.clone(), e, d_value.clone(), vec![p, q])
        .map_err(|err| StrongNameError::new(format!("invalid private key: {err}")))?;
    Ok((n, d_value))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::rand_core::{CryptoRng, RngCore};
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    /// Deterministic xorshift RNG so key generation (and therefore every
    /// assertion) is reproducible without extra dependencies.
    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> std::result::Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    /// Generates a deterministic 1024-bit RSA key.
    fn generate_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::new(&mut TestRng(0x5eed_1234_abcd_ef01), 1024).expect("keygen failed")
    }

    /// Serializes a full key pair as an `RSA2` private `.snk` blob, mirroring
    /// what `sn -k` writes.
    fn private_snk(key: &rsa::RsaPrivateKey) -> Vec<u8> {
        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();
        let d = key.d().to_bytes_be();
        let primes = key.primes();
        assert_eq!(primes.len(), 2, "expected a two-prime key");
        let (p, q) = (primes[0].to_bytes_be(), primes[1].to_bytes_be());

        let byte_len = n.len();
        let half_len = byte_len / 2;

        // dp = d mod (p-1), dq = d mod (q-1), qinv = q^(p-2) mod p.
        let dp = (key.d() % (&primes[0] - 1u32)).to_bytes_be();
        let dq = (key.d() % (&primes[1] - 1u32)).to_bytes_be();
        let qinv = primes[1].modpow(&(&primes[0] - 2u32), &primes[0]).to_bytes_be();

        let mut blob = Vec::with_capacity(20 + 4 * byte_len);
        blob.push(0x07); // PRIVATEKEYBLOB
        blob.push(0x02); // version
        blob.extend_from_slice(&[0, 0]); // reserved
        blob.extend_from_slice(&CALG_RSA_SIGN.to_le_bytes()); // ALGID
        blob.extend_from_slice(b"RSA2"); // DWORD magic = 0x32415352
        blob.extend_from_slice(&((byte_len as u32) * 8).to_le_bytes()); // bitlen
        blob.extend_from_slice(&le_field(&e, 4)); // pubexp DWORD
        blob.extend_from_slice(&le_field(&n, byte_len));
        blob.extend_from_slice(&le_field(&p, half_len));
        blob.extend_from_slice(&le_field(&q, half_len));
        blob.extend_from_slice(&le_field(&dp, half_len));
        blob.extend_from_slice(&le_field(&dq, half_len));
        blob.extend_from_slice(&le_field(&qinv, half_len));
        blob.extend_from_slice(&le_field(&d, byte_len));
        blob
    }

    /// Serializes a bare `RSA1` public blob.
    fn public_snk(key: &rsa::RsaPrivateKey) -> Vec<u8> {
        to_capi_public_blob(&key.n().to_bytes_be(), &key.e().to_bytes_be())
    }

    /// Builds a synthetic minimal PE32/CLI image; returns the bytes plus the
    /// file offset of the strong-name signature directory.
    fn tiny_pe(sn_size: usize) -> (Vec<u8>, usize) {
        const TEXT_RVA: u32 = 0x2000;
        const TEXT_RAW: usize = 0x200;

        let mut pe = vec![0u8; TEXT_RAW + 0x300];

        // DOS header.
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature + COFF header.
        let pe_sig = 0x80usize;
        pe[pe_sig..pe_sig + 4].copy_from_slice(b"PE\0\0");
        pe[pe_sig + 4..pe_sig + 6].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        pe[pe_sig + 6..pe_sig + 8].copy_from_slice(&1u16.to_le_bytes()); // sections
        pe[pe_sig + 20..pe_sig + 22].copy_from_slice(&0xe0u16.to_le_bytes()); // opt size
        pe[pe_sig + 22..pe_sig + 24].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics

        // Optional header (PE32).
        let opt = pe_sig + 24;
        pe[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // magic
        pe[opt + 64..opt + 68].copy_from_slice(&0u32.to_le_bytes()); // checksum slot
        pe[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // number of dirs

        // Data directory 14 = CLI header (rva, size).
        let dd = opt + 96;
        pe[dd + 14 * 8..dd + 14 * 8 + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
        pe[dd + 14 * 8 + 4..dd + 14 * 8 + 8].copy_from_slice(&0x48u32.to_le_bytes());

        // Section table.
        let sec = opt + 0xe0;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size
        pe[sec + 12..sec + 16].copy_from_slice(&TEXT_RVA.to_le_bytes()); // VA
        pe[sec + 16..sec + 20].copy_from_slice(&0x300u32.to_le_bytes()); // raw size
        pe[sec + 20..sec + 24].copy_from_slice(&(TEXT_RAW as u32).to_le_bytes()); // raw ptr
        pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics

        // CLI header at the start of .text.
        let cli = TEXT_RAW;
        pe[cli..cli + 4].copy_from_slice(&0x48u32.to_le_bytes()); // cb
        pe[cli + 4..cli + 6].copy_from_slice(&2u16.to_le_bytes()); // runtime major
        pe[cli + 6..cli + 8].copy_from_slice(&5u16.to_le_bytes()); // runtime minor
        pe[cli + 8..cli + 12].copy_from_slice(&(TEXT_RVA + 0x100).to_le_bytes()); // metadata rva
        pe[cli + 16..cli + 20].copy_from_slice(&1u32.to_le_bytes()); // ILONLY flag
        pe[cli + 20..cli + 24].copy_from_slice(&0x6000_0011u32.to_le_bytes()); // entrypoint
        pe[cli + 32..cli + 36].copy_from_slice(&(TEXT_RVA + 0x200).to_le_bytes()); // SN rva
        pe[cli + 36..cli + 40].copy_from_slice(&(sn_size as u32).to_le_bytes()); // SN size

        // Some pseudo-metadata noise so the hashed payload is non-trivial.
        for (i, byte) in b"cecli synthetic metadata root BSJB v1".iter().enumerate() {
            pe[TEXT_RAW + 0x100 + i] = *byte;
        }

        let sn_offset = TEXT_RAW + 0x200;
        (pe, sn_offset)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(hex(&sha1_digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1_digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // 100 bytes forces multi-block padding past the 55-byte boundary.
        let long = vec![b'a'; 100];
        assert_eq!(hex(&sha1_digest(&long)), "7f9000257a4918d7072655ea468540cdcbd42e0c");
    }

    #[test]
    fn snk_private_blob_roundtrip() {
        let key = generate_key();
        let blob = private_snk(&key);

        let pair = StrongNameKeyPair::new(&blob).expect("private snk should parse");
        assert!(!pair.is_public_only());

        let parsed = from_capi_key_blob(&blob).unwrap();
        assert_eq!(parsed.modulus, key.n().to_bytes_be());
        assert_eq!(parsed.exponent, key.e().to_bytes_be());
        assert!(parsed.is_private());

        // Re-serializing the parsed key must reproduce the input byte count
        // and all components (roundtrip through CryptoConvert's shape).
        let reserialized = to_capi_private_blob(&parsed).expect("re-serialize should work");
        let reparsed = from_capi_key_blob(&reserialized).unwrap();
        assert_eq!(reparsed.modulus, parsed.modulus);
        assert_eq!(reparsed.d, parsed.d);
        assert_eq!(reparsed.prime1, parsed.prime1);

        // public_key() must be the ECMA layout: 12-byte header + RSA1 blob.
        let public = pair.public_key();
        assert_eq!(public.len(), 12 + 20 + 128);
        assert_eq!(public[1], 36);
        assert_eq!(public[4], 4);
        assert_eq!(public[5], 128);
        let public_parsed = from_capi_key_blob(&public).expect("public key should parse");
        assert!(!public_parsed.is_private());
        assert_eq!(public_parsed.modulus, key.n().to_bytes_be());
    }

    #[test]
    fn snk_public_only_passthrough_and_sign_error() {
        let key = generate_key();
        let blob = public_snk(&key);

        let pair = StrongNameKeyPair::new(&blob).expect("public snk should parse");
        assert!(pair.is_public_only());
        // Public-only .snk passes straight through.
        assert_eq!(pair.public_key(), blob);

        let (mut image, _) = tiny_pe(128);
        let result = pair.sign_image(&mut image);
        assert!(
            matches!(&result, Err(err) if err.message.contains("public-only")),
            "public-only key must refuse to sign, got {result:?}"
        );

        // Garbage blobs are rejected up front too.
        assert!(StrongNameKeyPair::new(&[1, 2, 3]).is_err());
        assert!(StrongNameKeyPair::new(&[]).is_err());
    }

    #[test]
    fn headered_public_blob_parses_and_passes_through() {
        let key = generate_key();
        let ecma = ecma_public_key(&key.n().to_bytes_be(), &key.e().to_bytes_be());

        let pair = StrongNameKeyPair::new(&ecma).expect("headered public blob should parse");
        assert!(pair.is_public_only());
        assert_eq!(pair.public_key(), ecma);
    }

    /// Recomputes the digest a verifier sees over a signed image: the SN
    /// slot is conceptually zeroed again, but the patched checksum field
    /// stays intact — exactly the state `CryptoService.HashStream` hashed.
    fn verifier_digest(image: &[u8]) -> (PeLayout, Vec<u8>, u32) {
        let layout = pe_layout(image).unwrap();
        let mut copy = image.to_vec();
        copy[layout.sn_pointer..layout.sn_pointer + layout.sn_size].fill(0);
        let digest = hash_image(&copy, &layout, SignatureHashAlgorithm::Sha1).unwrap();
        let stored_checksum = u32::from_le_bytes(
            image[layout.checksum_offset..layout.checksum_offset + 4].try_into().unwrap(),
        );
        (layout, digest, stored_checksum)
    }

    #[test]
    fn sign_tiny_pe_and_verify_with_public_key() {
        let key = generate_key();
        let pair = StrongNameKeyPair::new(&private_snk(&key)).unwrap();

        let (mut image, sn_offset) = tiny_pe(128);
        pair.sign_image(&mut image).expect("signing should succeed");

        // A signature now occupies the directory slot.
        assert!(image[sn_offset..sn_offset + 128].iter().any(|&b| b != 0));

        // Verify the signature against the public key.
        let (layout, digest, _checksum) = verifier_digest(&image);
        let signature = &image[sn_offset..sn_offset + 128];
        assert!(
            pkcs1_v15_verify(&key.n(), &key.e(), SignatureHashAlgorithm::Sha1, &digest, signature),
            "signature must verify against the generated public key"
        );

        // The stored checksum must equal a fresh recomputation over the
        // pre-signature content (checksum field and SN slot zeroed) — the
        // exact state Cecil's pipeline hashes.
        let mut probe = image.clone();
        probe[layout.checksum_offset..layout.checksum_offset + 4].fill(0);
        probe[layout.sn_pointer..layout.sn_pointer + layout.sn_size].fill(0);
        let expected = patch_probe_checksum(&probe);
        assert_eq!(_checksum, expected);
    }

    /// Independent checksum implementation guarding against a bug shared
    /// between `patch_pe_checksum` and the signer.
    fn patch_probe_checksum(data: &[u8]) -> u32 {
        let mut sum: u64 = 0;
        let words = data.len() / 2;
        for i in 0..words {
            sum += u16::from_le_bytes([data[2 * i], data[2 * i + 1]]) as u64;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum = (sum & 0xffff) + (sum >> 16);
        (sum as u32).wrapping_add(data.len() as u32)
    }

    #[test]
    fn sign_tiny_pe_sha256() {
        let key = generate_key();
        let pair = StrongNameKeyPair::new(&private_snk(&key)).unwrap();

        let (mut image, sn_offset) = tiny_pe(128);
        pair.sign_image_with(&mut image, SignatureHashAlgorithm::Sha256)
            .expect("sha256 signing should succeed");

        // Recompute both digests over the signed image.
        let layout = pe_layout(&image).unwrap();
        let mut copy = image.clone();
        copy[layout.sn_pointer..layout.sn_pointer + layout.sn_size].fill(0);
        let mut buf = Vec::new();
        buf.extend_from_slice(&copy[..layout.header_size]);
        buf.extend_from_slice(&copy[layout.text_pointer..layout.sn_pointer]);
        buf.extend_from_slice(&copy[layout.sn_pointer + layout.sn_size..]);
        use sha2::Digest;
        let digest256 = sha2::Sha256::digest(&buf).to_vec();
        assert_eq!(digest256.len(), 32);

        let signature = &image[sn_offset..sn_offset + 128];
        assert!(
            pkcs1_v15_verify(
                &key.n(),
                &key.e(),
                SignatureHashAlgorithm::Sha256,
                &digest256,
                signature
            ),
            "sha256 signature must verify"
        );
        // ...and must NOT verify under SHA-1.
        let digest1 = sha1_digest(&buf);
        assert!(!pkcs1_v15_verify(
            &key.n(),
            &key.e(),
            SignatureHashAlgorithm::Sha1,
            &digest1,
            signature
        ));
    }

    #[test]
    fn sign_requires_signature_directory() {
        let key = generate_key();
        let pair = StrongNameKeyPair::new(&private_snk(&key)).unwrap();

        // Zero-sized strong-name directory must be rejected (Cecil throws
        // InvalidOperationException in the same situation).
        let (mut image, _) = tiny_pe(0);
        let cli = 0x200;
        image[cli + 32..cli + 36].copy_from_slice(&0u32.to_le_bytes());
        image[cli + 36..cli + 40].copy_from_slice(&0u32.to_le_bytes());
        assert!(pair.sign_image(&mut image).is_err());

        // Non-PE input must be rejected as well.
        let mut junk = vec![0u8; 64];
        junk[0] = b'M';
        junk[1] = b'Z';
        assert!(pair.sign_image(&mut junk).is_err());
    }
}
