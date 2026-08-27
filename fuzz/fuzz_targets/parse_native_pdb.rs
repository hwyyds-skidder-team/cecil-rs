#![no_main]

//! Fuzzes the native PDB reader: MSF container plus CodeView symbol and
//! line-number streams.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cecli_pdb::native::NativePdbReader::open(data);
});
