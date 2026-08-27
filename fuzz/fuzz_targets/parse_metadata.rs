#![no_main]

//! Fuzzes the raw BSJB metadata-root parser directly. Inputs without a
//! valid root signature reject immediately; corpus seeds (real metadata
//! blobs inside PE files) let mutations reach the table/heap decoders.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cecli_metadata::MetadataReader::parse(data);
});
