//! Exports a real native-preserving edit for independent dnlib inspection.
//! cargo run -p cecil-rs --example mixed_mode_edit -- fixtures/MixedNativeCLI.exe target/harden/MixedNativeCLI.edited.exe
use cecil::model::types::{RInstruction, ROperand};
use cecil::AssemblyDefinition;

fn main() -> cecil_core::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().ok_or_else(|| cecil_core::Error::argument("missing input PE path"))?;
    let output =
        args.next().ok_or_else(|| cecil_core::Error::argument("missing output PE path"))?;
    let mut assembly = AssemblyDefinition::read_file(input)?;
    let (id, _) = assembly
        .main
        .iter_methods()
        .find(|(_, method)| {
            method.body.as_ref().is_some_and(|b| {
                b.exception_handlers.is_empty()
                    && b.instructions
                        .iter()
                        .all(|i| !matches!(i.operand, ROperand::Branch(_) | ROperand::Switch(_)))
            })
        })
        .ok_or_else(|| cecil_core::Error::argument("input has no straight-line managed body"))?;
    let body = assembly.main.methods[id.index()].body.as_mut().unwrap();
    body.instructions.insert(
        0,
        RInstruction {
            offset: 0,
            opcode: cecil_cil::opcodes::LDSTR,
            operand: ROperand::String("cecil native-preserving edit 中文".into()),
        },
    );
    body.instructions.insert(
        1,
        RInstruction { offset: 5, opcode: cecil_cil::opcodes::POP, operand: ROperand::None },
    );
    cecil::edit::renumber(body);
    assembly.write_file(output)?;
    Ok(())
}
