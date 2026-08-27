#![no_main]

//! Fuzzes the Mono MDB symbol-format reader.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cecli_mdb::reader::MdbReader::open(data);
});
