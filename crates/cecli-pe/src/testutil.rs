//! Synthetic image builders shared by the `cecli-pe` unit tests.

use cecli_core::io::ByteWriter;

/// RVA of the first synthetic section (`.abc`).
pub const SEC1_VA: u32 = 0x1000;
/// RVA of the second synthetic section (`.def`).
pub const SEC2_VA: u32 = 0x2000;
/// RVA of the CLI header inside `.abc`.
pub const CLI_RVA: u32 = SEC1_VA;
/// RVA of the metadata root inside `.abc`.
pub const META_RVA: u32 = SEC1_VA + 0x100;
/// Entry-point token baked into the synthetic image.
pub const ENTRY_TOKEN: u32 = 0x0600_0001;
/// TimeDateStamp baked into the synthetic image.
pub const TIMESTAMP: u32 = 0x1234_5678;

/// The complete BSJB metadata root used by the synthetic image.
///
/// Version string "v4", zero streams.
pub fn tiny_metadata_root() -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u32(0x424A_5342); // BSJB
    w.u16(1); // MajorVersion
    w.u16(1); // MinorVersion
    w.u32(0); // Reserved
    w.u32(4); // Version length
    w.bytes(b"v4\0\0");
    w.u16(0); // Flags
    w.u16(0); // Stream count
    w.into_vec()
}

/// Builds a minimal but valid PE32 CLI image (I386, two sections) that
/// [`crate::Image::parse`] accepts.
pub fn tiny_image() -> Vec<u8> {
    let mut w = ByteWriter::new();

    // DOS header
    w.u16(0x5A4D); // 'MZ'
    w.zeros(58); // up to 0x3C
    debug_assert_eq!(w.position(), 0x3C);
    w.u32(0x40); // e_lfanew

    // PE signature + file header
    w.u32(0x0000_4550);
    w.u16(0x014C); // Machine = I386
    w.u16(2); // NumberOfSections
    w.u32(TIMESTAMP);
    w.u32(0); // PointerToSymbolTable
    w.u32(0); // NumberOfSymbols
    w.u16(0xE0); // SizeOfOptionalHeader
    w.u16(0x0102 | 0x0020); // ExecutableImage | 32BitMachine | LargeAddressAware

    // Optional header (PE32)
    w.u16(0x010B); // Magic
    w.u16(8); // LinkerVersion
    w.u32(0x400); // SizeOfCode
    w.u32(0x400); // SizeOfInitializedData
    w.u32(0); // SizeOfUninitializedData
    w.u32(SEC1_VA); // AddressOfEntryPoint
    w.u32(SEC1_VA); // BaseOfCode
    w.u32(0); // BaseOfData
    w.u32(0x0040_0000); // ImageBase
    w.u32(0x2000); // SectionAlignment
    w.u32(0x200); // FileAlignment
    w.u16(4); // OS major
    w.u16(0);
    w.u16(0); // Image major
    w.u16(0);
    w.u16(4); // Subsystem major
    w.u16(0);
    w.u32(0); // Win32VersionValue
    w.u32(0x4000); // SizeOfImage
    w.u32(0x200); // SizeOfHeaders
    w.u32(0); // Checksum
    w.u16(3); // SubSystem = Console
    w.u16(0x0540); // DllCharacteristics
    w.u32(0x0010_0000); // StackReserve
    w.u32(0x1000);
    w.u32(0x0010_0000); // HeapReserve
    w.u32(0x1000);
    w.u32(0); // LoaderFlags
    w.u32(16); // NumberOfRvaAndSizes

    // Data directories: only the COM+ directory is populated.
    for i in 0..16u32 {
        if i == 14 {
            w.u32(CLI_RVA);
            w.u32(0x48);
        } else {
            w.u32(0);
            w.u32(0);
        }
    }

    // Section headers (cursor is now at 0x138; headers end at 0x188).
    write_section_header(&mut w, b".abc", SEC1_VA, 0x400, 0x400, 0x200);
    write_section_header(&mut w, b".def", SEC2_VA, 0x200, 0x200, 0x600);

    // .abc content: CLI header at CLI_RVA (file 0x200).
    pad_to(&mut w, 0x200);
    w.u32(0x48); // Cb
    w.u16(2); // MajorRuntimeVersion
    w.u16(5); // MinorRuntimeVersion
    w.u32(META_RVA);
    w.u32(tiny_metadata_root().len() as u32);
    w.u32(1); // Flags = ILONLY
    w.u32(ENTRY_TOKEN);
    for _ in 0..6 {
        w.u32(0); // Resources, StrongName, CodeManager, VTableFixups,
                  // EATJumps, ManagedNative
    }

    // .abc content: metadata root at META_RVA (file 0x300).
    pad_to(&mut w, 0x300);
    w.bytes(&tiny_metadata_root());

    // Pad out to cover both sections' raw data (ends at 0x800).
    pad_to(&mut w, 0x800);

    w.into_vec()
}

fn write_section_header(
    w: &mut ByteWriter,
    name: &[u8; 4],
    va: u32,
    vsize: u32,
    srd: u32,
    ptr: u32,
) {
    w.bytes(name);
    w.zeros(4); // name padding
    w.u32(vsize);
    w.u32(va);
    w.u32(srd);
    w.u32(ptr);
    w.zeros(16); // relocs, line numbers, counts, characteristics
}

fn pad_to(w: &mut ByteWriter, offset: usize) {
    while w.len() < offset {
        w.u8(0);
    }
}
