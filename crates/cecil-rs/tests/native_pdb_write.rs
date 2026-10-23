use cecil::assembly::{build_native_pdb, SymbolOutput, WriteParameters};
use cecil::model::types::{RInstruction, ROperand};
use cecil::{AssemblyDefinition, Module};
use cecil_core::TableIndex;
use cecil_pdb::native::NativePdbReader;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(cecil_core::fixtures_dir().join(name)).unwrap()
}

fn native_options() -> WriteParameters {
    WriteParameters { symbol_output: Some(SymbolOutput::NativePdb), ..Default::default() }
}

fn output_directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/harden/native-facade")
}

fn symbol_reader_options() -> cecil::resolver::ReaderParameters {
    cecil::resolver::ReaderParameters { read_symbols: true, ..Default::default() }
}

#[test]
fn mixed_il_and_native_pdb_write_keeps_native_bytes_and_updated_sequence_points() {
    let original = fixture("MixedNativeCLI.exe");
    let before = cecil_pe::Image::parse(&original).unwrap();
    let mut assembly = AssemblyDefinition::read_file_with(
        cecil_core::fixtures_dir().join("MixedNativeCLI.exe"),
        &symbol_reader_options(),
    )
    .unwrap();
    let native_functions: Vec<_> = assembly
        .main
        .native_debug
        .as_ref()
        .unwrap()
        .functions
        .iter()
        .filter(|function| function.token.is_none())
        .cloned()
        .collect();
    let index = assembly
        .main
        .methods
        .iter()
        .position(|method| {
            method.body.as_ref().is_some_and(|body| {
                body.exception_handlers.is_empty()
                    && body
                        .instructions
                        .iter()
                        .all(|i| !matches!(i.operand, ROperand::Branch(_) | ROperand::Switch(_)))
            })
        })
        .unwrap();
    assembly.main.methods[index].body.as_mut().unwrap().instructions.insert(
        0,
        RInstruction { offset: 0, opcode: cecil_cil::opcodes::NOP, operand: ROperand::None },
    );
    cecil::edit::renumber(assembly.main.methods[index].body.as_mut().unwrap());
    // The debug model uses absolute IL offsets, as portable PDB output does.
    // Update it alongside the IL edit, retaining all local/type annotations.
    let debug = assembly.main.debug.as_mut().unwrap();
    if let Some(groups) = debug.points.get_mut(&(index as u32 + 1)) {
        for (_, points) in groups {
            for point in points {
                point.offset += 1;
            }
        }
    }
    if let Some(scopes) = debug.scopes.get_mut(&(index as u32 + 1)) {
        for scope in scopes.iter_mut().skip(1) {
            scope.try_start += 1;
        }
    }
    let expected_points = debug.points.clone();
    let out_dir = output_directory();
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("EditedMixed.exe");
    assembly.write_file_with(&path, &native_options()).unwrap();
    let output = std::fs::read(&path).unwrap();
    let after = cecil_pe::Image::parse(&output).unwrap();
    let cli = before.rva_offset(before.cli_directory.virtual_address as u64).unwrap();
    for (index, section) in before.sections.iter().enumerate() {
        assert_eq!(after.sections[index].virtual_address, section.virtual_address);
        assert_eq!(after.sections[index].pointer_to_raw_data, section.pointer_to_raw_data);
        assert_eq!(after.sections[index].size_of_raw_data, section.size_of_raw_data);
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;
        let mut expected = original[start..end].to_vec();
        if (start..end).contains(&cli) {
            expected[cli - start + 8..cli - start + 16].copy_from_slice(&output[cli + 8..cli + 16]);
        }
        assert_eq!(&output[start..end], expected);
    }
    let codeview = after.debug_entries.iter().find(|entry| entry.directory.kind == 2).unwrap();
    assert_eq!(&codeview.data[24..], b"EditedMixed.pdb\0");
    let pdb = std::fs::read(path.with_extension("pdb")).unwrap();
    let reader = NativePdbReader::open(&pdb).unwrap();
    let (guid, _, _, age) = reader.pdb_id();
    let original_pdb = fixture("MixedNativeCLI.pdb");
    let original_id = NativePdbReader::open(&original_pdb).unwrap().pdb_id();
    assert_ne!((guid, age), (original_id.0, original_id.3));
    assert_eq!(
        assembly.write_with(&native_options()).unwrap(),
        assembly.write_with(&native_options()).unwrap()
    );
    assert_eq!(&codeview.data[4..20], &guid);
    assert_eq!(&codeview.data[20..24], &age.to_le_bytes());
    let written_native: Vec<_> = reader
        .function_debug_info()
        .iter()
        .filter(|function| function.token.is_none())
        .cloned()
        .collect();
    assert_eq!(written_native, native_functions);
    let checksum = after.debug_entries.iter().find(|entry| entry.directory.kind == 19).unwrap();
    assert_eq!(checksum.data, cecil_pdb::embedded::pdb_checksum_payload(&pdb));
    let reread = AssemblyDefinition::read_file_with(&path, &symbol_reader_options()).unwrap();
    assert_eq!(reread.main.native_method_rvas, assembly.main.native_method_rvas);
    assert_eq!(reread.main.debug.as_ref().unwrap().points, expected_points);
    assert_eq!(
        reread.main.methods[index].body.as_ref().unwrap().instructions[0].opcode,
        cecil_cil::opcodes::NOP
    );
    assert_eq!(reread.write().unwrap(), output);
}

#[test]
fn managed_module_can_emit_native_pdb_without_an_original_type_stream() {
    let mut assembly = AssemblyDefinition::read(&fixture("hello.exe")).unwrap();
    let debug = cecil::module_def::ModuleDebugInfo {
        documents: vec![cecil_pdb::document::Document {
            name: "hello.cs".into(),
            hash_algorithm: [0; 16],
            hash: Vec::new(),
            language: [0; 16],
        }],
        points: std::collections::BTreeMap::from([(
            1,
            vec![(
                0,
                vec![cecil_pdb::portable_reader::SequencePoint {
                    offset: 0,
                    start_line: 3,
                    end_line: 3,
                    start_column: 1,
                    end_column: 12,
                }],
            )],
        )]),
        ..Default::default()
    };
    assembly.main.debug = Some(debug);
    let pdb = build_native_pdb(&assembly.main).unwrap();
    let reader = NativePdbReader::open(&pdb).unwrap();
    assert!(reader.function_debug_info().iter().any(|function| function
        .token
        .is_some_and(|token| token.table_byte() == TableIndex::MethodDef as u8)
        && function.lines.iter().any(|line| line.file == "hello.cs")));
    let output = assembly.write_with(&native_options()).unwrap();
    let image = cecil_pe::Image::parse(&output).unwrap();
    assert_eq!(image.debug_entries.iter().filter(|entry| entry.directory.kind == 2).count(), 1);
    assert_eq!(
        image.debug_entries.iter().find(|entry| entry.directory.kind == 19).unwrap().data,
        cecil_pdb::embedded::pdb_checksum_payload(&pdb)
    );
    AssemblyDefinition::read(&output).unwrap();
    let empty = build_native_pdb(&Module::default()).unwrap();
    NativePdbReader::open(&empty).unwrap();
}

#[test]
fn native_pdb_attachment_rejects_signed_native_images() {
    let mut bytes = fixture("MixedNativeCLI.exe");
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    bytes[cli + 16..cli + 20].copy_from_slice(&(image.cli_header.flags | 8).to_le_bytes());
    let assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert!(matches!(
        assembly.write_with(&native_options()),
        Err(cecil_core::Error::Unsupported(_))
    ));
}

#[test]
fn mixed_images_can_convert_symbols_to_portable_or_embedded_pdb() {
    let assembly = AssemblyDefinition::read_file_with(
        cecil_core::fixtures_dir().join("MixedNativeCLI.exe"),
        &symbol_reader_options(),
    )
    .unwrap();
    let mut expected = assembly.main.debug.as_ref().unwrap().points.clone();
    for groups in expected.values_mut() {
        for (_, points) in groups {
            points.reverse();
            for point in points.iter_mut() {
                if !point.is_hidden()
                    && point.start_line == point.end_line
                    && point.start_column == point.end_column
                {
                    point.end_column += 1;
                }
            }
            points.dedup_by_key(|point| point.offset);
            points.reverse();
        }
    }
    for output in [SymbolOutput::PortablePdb, SymbolOutput::EmbeddedPortablePdb, SymbolOutput::Mdb]
    {
        let out_dir = output_directory();
        std::fs::create_dir_all(&out_dir).unwrap();
        let path = out_dir.join(format!("Converted{output:?}.exe"));
        let options = WriteParameters { symbol_output: Some(output), ..Default::default() };
        assembly.write_file_with(&path, &options).unwrap();
        let reread = AssemblyDefinition::read_file_with(&path, &symbol_reader_options())
            .unwrap_or_else(|error| panic!("{output:?}: {error}"));
        assert_eq!(reread.main.native_method_rvas, assembly.main.native_method_rvas);
        assert!(!reread.main.debug.as_ref().unwrap().points.is_empty());
        if output != SymbolOutput::Mdb {
            assert_eq!(reread.main.debug.as_ref().unwrap().points, expected);
        }
    }
}

#[test]
fn mixed_pdb_local_slots_follow_appended_local_signature_tokens() {
    let mut assembly = AssemblyDefinition::read_file_with(
        cecil_core::fixtures_dir().join("MixedNativeCLI.exe"),
        &symbol_reader_options(),
    )
    .unwrap();
    let function = assembly
        .main
        .native_debug
        .as_ref()
        .unwrap()
        .functions
        .iter()
        .find(|function| {
            function.token.is_some()
                && function.scopes.iter().any(|scope| {
                    scope.locals.iter().any(|local| {
                        local.index.is_some()
                            && local.type_index >> 24 == TableIndex::StandAloneSig as u32
                    })
                })
        })
        .unwrap();
    let token = function.token.unwrap();
    let body = assembly.main.methods[token.rid() as usize - 1].body.as_mut().unwrap();
    body.locals.push(cecil::model::types::LocalVariable {
        ty: cecil::model::types::TypeDesc::Internal("int32".into()),
        pinned: false,
        index: body.locals.len() as u16,
    });
    let out_dir = output_directory();
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("ChangedLocals.exe");
    assembly.write_file_with(&path, &native_options()).unwrap();
    let reread = AssemblyDefinition::read_file_with(&path, &symbol_reader_options()).unwrap();
    let body = reread.main.methods[token.rid() as usize - 1].body.as_ref().unwrap();
    let function = reread
        .main
        .native_debug
        .as_ref()
        .unwrap()
        .functions
        .iter()
        .find(|function| function.token == Some(token))
        .unwrap();
    for local in function.scopes.iter().flat_map(|scope| &scope.locals) {
        if local.type_index >> 24 == TableIndex::StandAloneSig as u32 {
            assert_eq!(local.type_index, body.local_var_sig_tok.0);
        }
    }
}

#[test]
fn managed_native_pdb_uses_final_local_signature_allocations() {
    let mut assembly = AssemblyDefinition::read(&fixture("hello.exe")).unwrap();
    let index = assembly.main.methods.iter().position(|method| method.body.is_some()).unwrap();
    let body = assembly.main.methods[index].body.as_mut().unwrap();
    body.locals.push(cecil::model::types::LocalVariable {
        index: 0,
        ty: cecil::model::types::TypeDesc::Internal("int32".into()),
        pinned: false,
    });
    let mut scope = cecil_pdb::native::NativeScope {
        parent: None,
        offset: 0,
        length: 0,
        locals: Vec::new(),
        constants: Vec::new(),
        imports: Vec::new(),
    };
    scope.locals.push(cecil_pdb::native::NativeLocal {
        name: "value".into(),
        index: Some(0),
        type_index: 0x1100_0077,
        flags: 0,
    });
    let token = cecil_core::Token::new(TableIndex::MethodDef, index as u32 + 1);
    assembly.main.native_debug = Some(cecil::module_def::NativeModuleDebugInfo {
        functions: vec![cecil_pdb::native::FunctionDebugInfo {
            token: Some(token),
            name: "Main".into(),
            module_index: 0,
            segment: 1,
            offset: 0,
            length: 0,
            rva: None,
            lines: Vec::new(),
            scopes: vec![scope],
        }],
        ..Default::default()
    });
    let out_dir = output_directory();
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("ManagedLocals.exe");
    assembly.write_file_with(&path, &native_options()).unwrap();
    let reread = AssemblyDefinition::read_file_with(&path, &symbol_reader_options()).unwrap();
    let signature = reread.main.methods[index].body.as_ref().unwrap().local_var_sig_tok;
    assert_ne!(signature.0, 0x1100_0077);
    let function = reread
        .main
        .native_debug
        .as_ref()
        .unwrap()
        .functions
        .iter()
        .find(|function| function.token == Some(token))
        .unwrap();
    assert_eq!(function.scopes[0].locals[0].type_index, signature.0);
}

#[test]
fn sidecar_path_collision_is_rejected_before_touching_output() {
    let assembly = AssemblyDefinition::read(&fixture("hello.exe")).unwrap();
    let out_dir = output_directory();
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("Collision.pdb");
    std::fs::write(&path, b"keep me").unwrap();
    assert!(matches!(
        assembly.write_file_with(&path, &native_options()),
        Err(cecil_core::Error::Argument(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    if cfg!(windows) {
        let upper_path = out_dir.join("Collision.PDB");
        assert!(assembly.write_file_with(&upper_path, &native_options()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    }
}
