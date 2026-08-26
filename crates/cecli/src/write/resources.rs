//! Managed (.NET) manifest-resource emission.
//!
//! Port of Mono.Cecil's resource writing: `Mono.Cecil.Metadata/Buffers.cs`
//! (`ResourceBuffer.AddResource`) plus `AssemblyWriter.AddResources`,
//! `AddEmbeddedResource` and the reader-side inverse
//! `AssemblyReader.GetManagedResource`.
//!
//! # Blob format (verified against Mono.Cecil)
//!
//! The CLI-header *Resources* directory holds one flat blob. It contains
//! **no** entry table: every managed resource stored here is laid out as
//!
//! ```text
//! [ i32 payload_length ][ payload bytes ... ]
//! ```
//!
//! back to back. The byte offset of an entry's `i32` length prefix is what
//! goes into the `Offset` column of the corresponding `ManifestResource`
//! metadata row. Rows whose implementation points at a `File` (linked
//! resource) or an `AssemblyRef` (assembly-linked resource) carry **no**
//! blob entry at all; their `Offset` column stays `0` - exactly what
//! Mono.Cecil emits (`row.Col1` initialised to 0 and never touched for
//! non-embedded kinds).
//!
//! Divergence from upstream: Mono.Cecil aligns only the *section* holding
//! the blob to 8 bytes (`ImageWriter.BuildTextMap`,
//! `map.AddMap (TextSegment.Resources, ..., 8)`), while entries themselves
//! are packed without padding. This port additionally starts every embedded
//! entry on an 8-byte boundary *inside* the blob. This is transparent to the
//! ECMA-335 runtime and readers because access always goes through the
//! explicit per-row offset; it keeps every recorded offset itself
//! 8-aligned, matching the intent of the segment-level alignment upstream.

use cecli_core::{Error, Result};

/// Magic found at the start of a managed `.resources` stream
/// (`System.Resources.ResourceReader`).
pub const MANAGED_RESOURCE_SIGNATURE: u32 = 0xBEEFCACE;

/// Alignment applied to each embedded resource entry start inside the blob.
///
/// Matches the 8-byte alignment Mono.Cecil applies to the resources segment.
pub const RESOURCE_ALIGNMENT: usize = 8;

/// Built `.NET` managed-resources blob plus the per-resource offsets.
///
/// `offsets[i]` is the value destined for the `Offset` column of the
/// i-th `ManifestResource` row (rows are emitted in the same order as
/// [`crate::module_def::Module::resources`]). Embedded resources point at the
/// `i32` length prefix of their payload inside `bytes`; linked and
/// assembly-linked resources contribute the Cecil placeholder `0` and have no
/// bytes in the blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcesBlob {
    /// Serialized blob contents (the CLI-header Resources directory image).
    pub bytes: Vec<u8>,
    /// One offset per input resource, in input order.
    pub offsets: Vec<usize>,
}

fn align_up(value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    value.div_ceil(alignment) * alignment
}

/// Builds the managed-resources blob for a module's resources, in arena order.
///
/// Mirrors `AssemblyWriter.AddResources` + `ResourceBuffer.AddResource`:
/// embedded payloads are appended as `i32 length + bytes`; linked and
/// assembly-linked resources get the `0` offset placeholder. Each embedded
/// entry begins on an 8-byte boundary (see [module docs](self)).
///
/// # Errors
/// Returns [`Error::Argument`] when an embedded payload exceeds
/// [`i32::MAX`] bytes (the length prefix cannot represent it) or when the
/// resulting blob exceeds `u32::MAX` bytes (offsets are 32-bit metadata
/// cells).
pub fn build_resources_blob(resources: &[crate::module_def::Resource]) -> Result<ResourcesBlob> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut offsets = Vec::with_capacity(resources.len());

    for resource in resources {
        let data = match resource {
            crate::module_def::Resource::Embedded { data, .. } => data,
            // Cecil leaves Col1 == 0 for File / AssemblyRef implementations.
            crate::module_def::Resource::Linked { .. }
            | crate::module_def::Resource::AssemblyLinked { .. } => {
                offsets.push(0);
                continue;
            }
        };

        let len = i32::try_from(data.len()).map_err(|_| {
            Error::argument(format!(
                "embedded resource {:?} is {} bytes; maximum is {}",
                resource.name(),
                data.len(),
                i32::MAX
            ))
        })?;

        // Start of this entry's i32 length prefix, 8-aligned within the blob.
        let offset = align_up(bytes.len(), RESOURCE_ALIGNMENT);
        bytes.resize(offset, 0);

        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(data);

        let end = bytes.len();
        u32::try_from(end).map_err(|_| {
            Error::argument(format!(
                "managed resources blob exceeds u32::MAX bytes ({} so far)",
                end
            ))
        })?;

        offsets.push(offset);
    }

    Ok(ResourcesBlob { bytes, offsets })
}

/// Reads one embedded resource payload out of a built resources blob.
///
/// Inverse of the writing side and of `AssemblyReader.GetManagedResource`:
/// seeks to `offset`, reads the `i32` length prefix, and returns exactly that
/// many bytes.
///
/// # Errors
/// Returns [`Error::BadImage`] when `offset` is out of bounds, the length
/// prefix is negative or larger than the remaining blob.
pub fn read_embedded_resource(blob: &[u8], offset: usize) -> Result<Vec<u8>> {
    let rest = blob.get(offset..).ok_or_else(|| {
        Error::bad_image(format!(
            "resource offset {offset} out of bounds (blob length {})",
            blob.len()
        ))
    })?;

    if rest.len() < 4 {
        return Err(Error::bad_image(format!("truncated resource header at offset {offset}")));
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&rest[..4]);
    let len = i32::from_le_bytes(len_bytes);

    if len < 0 {
        return Err(Error::bad_image(format!("negative resource length {len} at offset {offset}")));
    }

    let len = len as usize;
    let payload = rest.get(4..4 + len).ok_or_else(|| {
        Error::bad_image(format!(
            "resource at offset {offset} claims {len} bytes but only {} remain",
            rest.len() - 4
        ))
    })?;

    Ok(payload.to_vec())
}

/// Quick sanity check that `data` looks like a managed `.resources` stream:
/// it must start with [`MANAGED_RESOURCE_SIGNATURE`] and be long enough to
/// hold the fixed part of the header (magic + header version + header size).
pub fn validate_dotnet_resources(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == MANAGED_RESOURCE_SIGNATURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_def::Resource as Res;
    use cecli_core::flags::ManifestResourceAttributes;

    fn attrs() -> ManifestResourceAttributes {
        ManifestResourceAttributes::PUBLIC
    }

    /// Acceptance: 'A' embedded 5 B, 'B' linked placeholder, 'C' embedded
    /// 300 B forcing alignment between the two embedded entries.
    #[test]
    fn builds_blob_and_walks_entries() {
        let payload_a = b"12345".to_vec();
        let payload_c: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();

        let resources = vec![
            Res::Embedded { name: "A".to_string(), attributes: attrs(), data: payload_a.clone() },
            Res::Linked {
                name: "B".to_string(),
                attributes: attrs(),
                file: "data.bin".to_string(),
            },
            Res::Embedded { name: "C".to_string(), attributes: attrs(), data: payload_c.clone() },
        ];

        let blob = build_resources_blob(&resources).expect("blob builds");

        // One offset per resource, arena order preserved.
        assert_eq!(blob.offsets.len(), 3);

        // Linked placeholder: zero offset, nothing contributed to the blob
        // by resource B itself.
        assert_eq!(blob.offsets[1], 0);

        // Entries are 8-aligned inside the blob.
        assert_eq!(blob.offsets[0] % 8, 0);
        assert_eq!(blob.offsets[2] % 8, 0);

        // C cannot start directly after A (4 + 5 = 9 is unaligned), so the
        // alignment gap must have been inserted: everything between the end
        // of A's payload and C's entry start is zero padding.
        let gap_start = blob.offsets[0] + 4 + payload_a.len();
        assert_eq!(blob.offsets[2], gap_start.div_ceil(8) * 8);
        assert!(blob.bytes[gap_start..blob.offsets[2]].iter().all(|&b| b == 0));

        // Walk every entry through our own reader and compare against the
        // source model: name association comes from input order, sizes,
        // offsets and payloads must round-trip exactly.
        for (resource, &offset) in resources.iter().zip(&blob.offsets) {
            match resource {
                Res::Embedded { name, data, .. } => {
                    let got = read_embedded_resource(&blob.bytes, offset)
                        .unwrap_or_else(|e| panic!("read {name} failed: {e}"));
                    assert_eq!(&got, data, "payload mismatch for {name}");
                    // Length prefix matches the declared size.
                    let prefix =
                        i32::from_le_bytes(blob.bytes[offset..offset + 4].try_into().unwrap());
                    assert_eq!(prefix as usize, data.len(), "size mismatch for {name}");
                }
                Res::Linked { name, .. } => {
                    assert_eq!(offset, 0, "linked resource {name} must carry placeholder 0");
                }
                Res::AssemblyLinked { name, .. } => {
                    assert_eq!(
                        offset, 0,
                        "assembly-linked resource {name} must carry placeholder 0"
                    );
                }
            }
        }

        // Total consumed = last entry end; nothing trailing.
        let last_end = blob.offsets[2] + 4 + payload_c.len();
        assert_eq!(blob.bytes.len(), last_end);
    }

    #[test]
    fn empty_resource_list_gives_empty_blob() {
        let blob = build_resources_blob(&[]).expect("empty ok");
        assert!(blob.bytes.is_empty());
        assert!(blob.offsets.is_empty());
    }

    #[test]
    fn assembly_linked_gets_placeholder() {
        let asm_ref = crate::model::types::AssemblyNameReference::new("Ext");
        let resources = vec![Res::AssemblyLinked {
            name: "X".to_string(),
            attributes: attrs(),
            assembly: asm_ref,
        }];
        let blob = build_resources_blob(&resources).expect("ok");
        assert_eq!(blob.offsets, vec![0]);
        assert!(blob.bytes.is_empty());
    }

    #[test]
    fn read_embedded_resource_rejects_bad_input() {
        let good = build_resources_blob(&[Res::Embedded {
            name: "a".into(),
            attributes: attrs(),
            data: b"abcde".to_vec(),
        }])
        .unwrap();
        let off = good.offsets[0];

        // Out of bounds offset.
        assert!(read_embedded_resource(&good.bytes, good.bytes.len()).is_err());

        // Truncated header.
        assert!(read_embedded_resource(&good.bytes[..off + 2], off).is_err());

        // Claimed length beyond blob end: corrupt the length prefix to a
        // large positive value.
        let mut corrupted = good.bytes.clone();
        corrupted[off..off + 4].copy_from_slice(&(1_000_000i32).to_le_bytes());
        assert!(read_embedded_resource(&corrupted, off).is_err());

        // Negative length prefix.
        let mut neg = good.bytes.clone();
        neg[off..off + 4].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(read_embedded_resource(&neg, off).is_err());

        // Valid read still works after all that.
        assert_eq!(read_embedded_resource(&good.bytes, off).unwrap(), b"abcde");
    }

    #[test]
    fn large_but_valid_payload_succeeds() {
        // The i32::MAX / u32::MAX guards cannot be exercised without
        // multi-gigabyte allocations; verify a payload spanning several
        // alignment windows instead.
        let blob = build_resources_blob(&[Res::Embedded {
            name: "ok".into(),
            attributes: attrs(),
            data: vec![0u8; 4096],
        }])
        .expect("small payload fine");
        assert_eq!(blob.offsets, vec![0]);
    }

    #[test]
    fn validate_dotnet_resources_magic_and_len() {
        // Crafted valid stream: magic + version + header size.
        let mut valid = Vec::new();
        valid.extend_from_slice(&MANAGED_RESOURCE_SIGNATURE.to_le_bytes());
        valid.extend_from_slice(&1u32.to_le_bytes()); // header version
        valid.extend_from_slice(&28u32.to_le_bytes()); // header size
        assert!(validate_dotnet_resources(&valid));

        // Wrong magic.
        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xFF;
        assert!(!validate_dotnet_resources(&bad_magic));

        // Too short.
        assert!(!validate_dotnet_resources(&valid[..8]));
        assert!(!validate_dotnet_resources(&[]));

        // Random junk fails.
        assert!(!validate_dotnet_resources(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
    }

    #[test]
    fn offsets_are_deterministic_across_runs() {
        let mk = || {
            vec![
                Res::Embedded { name: "A".into(), attributes: attrs(), data: vec![7u8; 13] },
                Res::Linked { name: "B".into(), attributes: attrs(), file: "f".into() },
                Res::Embedded { name: "C".into(), attributes: attrs(), data: vec![9u8; 300] },
            ]
        };
        let a = build_resources_blob(&mk()).unwrap();
        let b = build_resources_blob(&mk()).unwrap();
        assert_eq!(a, b);
    }
}
