//! Regression coverage for malformed PropertyMap/EventMap rows found by
//! roundtrip fuzzing. Build small images without depending on ZIP artifacts.

use cecli::AssemblyDefinition;
use cecli_core::{token::coded, Error, TableIndex as T};
use cecli_metadata::{encode_coded, MetadataBuilder};
use cecli_pe::{EmitParts, Image, ImageWriter};

fn member_map_image(map: T, rows: &[(u32, u32)], member_count: u32) -> Vec<u8> {
    let mut builder = MetadataBuilder::new("v4.0.30319");
    let name = builder.insert_string("member_maps.netmodule");
    let guid = builder.insert_guid(&[7; 16]);
    builder.add_row(T::Module, &[0, name as u64, guid as u64, 0, 0]).unwrap();
    for name in ["<Module>", "First", "Second"] {
        let name = builder.insert_string(name);
        builder.add_row(T::TypeDef, &[0, name as u64, 0, 0, 1, 1]).unwrap();
    }
    for &(parent, start) in rows {
        builder.add_row(map, &[parent as u64, start as u64]).unwrap();
    }
    let property_sig = builder.insert_blob(&[0x08, 0x00, 0x08]); // PROPERTY, no params, I4
    let event_type = encode_coded(&coded::TYPE_DEF_OR_REF, T::TypeDef, 2).unwrap();
    for rid in 1..=member_count {
        let name = builder.insert_string(&format!("Member{rid}"));
        match map {
            T::PropertyMap => {
                builder.add_row(T::Property, &[0, name as u64, property_sig as u64]).unwrap();
            }
            T::EventMap => {
                builder.add_row(T::Event, &[0, name as u64, event_type]).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let carrier = AssemblyDefinition::default().write().unwrap();
    let image = Image::parse(&carrier).unwrap();
    ImageWriter::rebuild(&image, EmitParts { metadata: builder.finalize(), ..Default::default() })
        .emit()
        .unwrap()
}

fn assert_bad_map(map: T, rows: &[(u32, u32)], member_count: u32) {
    let bytes = member_map_image(map, rows, member_count);
    match AssemblyDefinition::read(&bytes) {
        Err(Error::BadImage(message)) => {
            assert!(message.contains(&format!("{map:?}")), "unexpected error: {message}");
        }
        Err(error) => panic!("{map:?} {rows:?}: expected BadImage, got {error}"),
        Ok(_) => panic!("{map:?} {rows:?}: malformed map was accepted"),
    }
}

fn owned_names(asm: &AssemblyDefinition, map: T) -> Vec<Vec<&str>> {
    let module = asm.main_module();
    module
        .types
        .iter()
        .map(|ty| match map {
            T::PropertyMap => {
                ty.properties.iter().map(|id| module.properties[id.index()].name.as_str()).collect()
            }
            T::EventMap => {
                ty.events.iter().map(|id| module.events[id.index()].name.as_str()).collect()
            }
            _ => unreachable!(),
        })
        .collect()
}

#[test]
fn member_maps_reject_invalid_parents() {
    for map in [T::PropertyMap, T::EventMap] {
        for parent in [0, 4, u16::MAX as u32] {
            assert_bad_map(map, &[(parent, 1)], 3);
        }
        // Empty ranges must not hide an invalid TypeDef reference either.
        assert_bad_map(map, &[(4, 1), (2, 1)], 3);
    }
}

#[test]
fn member_maps_reject_invalid_list_ranges() {
    for map in [T::PropertyMap, T::EventMap] {
        for rows in [
            &[][..],                       // Missing map leaves rows without owners.
            &[(2, 0)][..],                 // Nil list start.
            &[(2, 2)][..],                 // Unowned first row.
            &[(2, 5)][..],                 // Beyond the count + 1 sentinel.
            &[(2, 1), (3, 5)][..],         // Out-of-bounds end of the first run.
            &[(2, 1), (3, 0)][..],         // Nil start after a valid row.
            &[(1, 1), (2, 3), (3, 2)][..], // Decreasing starts duplicate rows.
        ] {
            assert_bad_map(map, rows, 3);
        }
    }
}

#[test]
fn member_maps_reject_duplicate_parents() {
    for map in [T::PropertyMap, T::EventMap] {
        assert_bad_map(map, &[(2, 1), (2, 2)], 3);
        assert_bad_map(map, &[(2, 1), (3, 2), (2, 3)], 3);
    }
}

#[test]
fn member_maps_preserve_ownership_across_roundtrip() {
    for map in [T::PropertyMap, T::EventMap] {
        for (rows, expected) in [
            (&[(2, 1), (3, 2)][..], vec![vec![], vec!["Member1"], vec!["Member2", "Member3"]]),
            (
                &[(3, 1), (2, 3)][..], // Parent order need not match member row order.
                vec![vec![], vec!["Member3"], vec!["Member1", "Member2"]],
            ),
            (
                &[(1, 1), (2, 1), (3, 3)][..], // Empty leading range.
                vec![vec![], vec!["Member1", "Member2"], vec!["Member3"]],
            ),
            (
                &[(2, 1), (3, 4)][..], // Empty final range at count + 1.
                vec![vec![], vec!["Member1", "Member2", "Member3"], vec![]],
            ),
        ] {
            let bytes = member_map_image(map, rows, 3);
            let mut asm = AssemblyDefinition::read(&bytes).unwrap();
            for round in 0..3 {
                let module = asm.main_module();
                assert_eq!(module.properties.len() + module.events.len(), 3);
                assert_eq!(owned_names(&asm, map), expected, "{map:?} {rows:?}, round {round}");
                if round < 2 {
                    asm = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
                }
            }
        }
    }
}

#[test]
fn member_maps_allow_empty_tables() {
    for map in [T::PropertyMap, T::EventMap] {
        for rows in [&[][..], &[(2, 1), (3, 1)][..]] {
            let bytes = member_map_image(map, rows, 0);
            let asm = AssemblyDefinition::read(&bytes).unwrap();
            let re = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
            for module in [asm.main_module(), re.main_module()] {
                assert!(module.properties.is_empty());
                assert!(module.events.is_empty());
            }
        }
    }
}
