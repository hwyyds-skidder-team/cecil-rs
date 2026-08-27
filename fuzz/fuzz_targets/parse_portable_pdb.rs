#![no_main]

//! Fuzzes the Portable PDB (ECMA-335 metadata with a `#Pdb` heap) reader.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cecli_pdb::portable_reader::PortablePdbReader::parse(data);
});
