#![no_main]

//! Property fuzz: whenever the reader accepts an image, the writer must
//! produce an image the reader accepts back with identical member counts.
//! This exercises the read -> write -> re-read invariant of
//! `tests/fixtures_roundtrip.rs` on adversarial inputs, where the writer
//! and the reader can disagree in ways the fixture corpus never hits.

use libfuzzer_sys::fuzz_target;

/// Member-count snapshot mirroring `tests/helpers::Counts` (kept inline:
/// the test helper module is not part of the library the fuzz crate links).
fn counts(m: &cecli::module_def::Module) -> (usize, usize, usize, usize, usize) {
    (m.types.len(), m.methods.len(), m.fields.len(), m.properties.len(), m.events.len())
}

fuzz_target!(|data: &[u8]| {
    let Ok(asm) = cecli::AssemblyDefinition::read(data) else { return };
    let before = counts(asm.main_module());

    // Writing a model the reader just produced must succeed; a panic or
    // error here is a writer bug reachable from (mutated) real images.
    let bytes = asm.write().expect("writer accepts what the reader produced");

    // Re-reading the writer's output must preserve member counts.
    let reparsed =
        cecli::AssemblyDefinition::read(&bytes).expect("writer output must re-read cleanly");
    let after = counts(reparsed.main_module());
    assert_eq!(before, after, "member counts changed across write -> re-read");
});
