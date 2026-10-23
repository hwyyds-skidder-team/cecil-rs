//! Rebuilds modeled native PDB records while retaining original type streams.

use cecil_core::{Error, Result};
use cecil_pdb::native::{
    FunctionDebugInfo, NativePdbBuilder, NativeScope, SourceDocument, SourceLine,
};

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let bytes = match arguments.as_slice() {
        [input, _output] => NativePdbBuilder::from_pdb(&std::fs::read(input)?)?.finalize()?,
        [_output] => {
            let mut builder = NativePdbBuilder::new();
            builder.set_identity([0x37; 16], 0x1234, 1);
            builder.add_document(SourceDocument {
                name: "example.cpp".into(),
                checksum_kind: 1,
                checksum: vec![1; 16],
            })?;
            builder.add_public("example", 1, 0x10, 2)?;
            builder.add_function(FunctionDebugInfo {
                token: None,
                name: "example".into(),
                module_index: 0,
                segment: 1,
                offset: 0x10,
                length: 16,
                rva: None,
                lines: vec![SourceLine {
                    rva: None,
                    offset: 0,
                    start_line: 5,
                    end_line: 5,
                    start_column: 1,
                    end_column: 12,
                    is_statement: true,
                    file: "example.cpp".into(),
                }],
                scopes: vec![NativeScope {
                    parent: None,
                    offset: 0,
                    length: 16,
                    locals: Vec::new(),
                    constants: Vec::new(),
                    imports: Vec::new(),
                }],
            })?;
            builder.finalize()?
        }
        _ => return Err(Error::argument("usage: native_pdb_rebuild [input.pdb] output.pdb")),
    };
    std::fs::write(arguments.last().unwrap(), bytes)?;
    Ok(())
}
