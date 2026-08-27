#![no_main]

//! Fuzzes the full read pipeline: bytes -> PE image -> metadata -> object
//! model -> method bodies. Every `Result` is expected to be an error for
//! random input; only panics, hangs, and sanitizer findings are failures.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cecli::AssemblyDefinition::read(data);
});
