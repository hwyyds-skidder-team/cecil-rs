use cecli::model::types::{MethodRef, MethodSignature, ROperand, ScopeRef, TypeDesc};
use cecli::AssemblyDefinition;

fn owned_nodes(ty: &TypeDesc) -> (usize, usize) {
    match ty {
        TypeDesc::Def(_)
        | TypeDesc::Var(_)
        | TypeDesc::MVar(_)
        | TypeDesc::Sentinel
        | TypeDesc::TypedByRef => (0, 0),
        TypeDesc::External(ext) => {
            let mut strings = 2 + ext.nesting.len() * 2;
            let mut vecs = 1;
            match &ext.scope {
                ScopeRef::Assembly(a) => {
                    strings += 1 + usize::from(a.culture.is_some());
                    vecs += 3;
                }
                ScopeRef::OtherModule(_) => strings += 1,
                _ => {}
            }
            (strings, vecs)
        }
        TypeDesc::Internal(_) => (1, 0),
        TypeDesc::SzArray(_) | TypeDesc::Ptr(_) | TypeDesc::ByRef(_) | TypeDesc::Pinned(_) => {
            (0, 0)
        }
        TypeDesc::Array { sizes, lobounds, .. } => {
            (0, usize::from(!sizes.is_empty()) + usize::from(!lobounds.is_empty()))
        }
        TypeDesc::GenericInstance { arguments, .. } => (0, usize::from(!arguments.is_empty())),
        TypeDesc::FnPtr(sig) => signature_nodes(sig),
        TypeDesc::CMod { .. } => (0, 0),
    }
}

fn signature_nodes(sig: &MethodSignature) -> (usize, usize) {
    let mut result = owned_nodes(&sig.return_type);
    result.1 += usize::from(!sig.parameters.is_empty());
    for ty in &sig.parameters {
        let n = owned_nodes(ty);
        result.0 += n.0;
        result.1 += n.1;
    }
    result
}

fn main() {
    let bytes = std::fs::read("fixtures/cecil.dll").unwrap();
    let asm = AssemblyDefinition::read(&bytes).unwrap();
    let mut uses = 0usize;
    let mut parent_def = 0usize;
    let mut parent_external = 0usize;
    let mut strings = 0usize;
    let mut vecs = 0usize;
    let mut specs = 0usize;
    for method in &asm.main.methods {
        let Some(body) = &method.body else { continue };
        for ins in &body.instructions {
            let ROperand::Method(reference) = &ins.operand else { continue };
            let external = match reference {
                MethodRef::External(external) => external,
                MethodRef::Spec { method, .. } => {
                    specs += 1;
                    let MethodRef::External(external) = method.as_ref() else { continue };
                    external
                }
                _ => continue,
            };
            uses += 1;
            match external.parent {
                TypeDesc::Def(_) => parent_def += 1,
                TypeDesc::External(_) => parent_external += 1,
                _ => {}
            }
            strings += 1;
            let n = owned_nodes(&external.parent);
            strings += n.0;
            vecs += n.1;
            let n = signature_nodes(&external.signature);
            strings += n.0;
            vecs += n.1;
        }
    }
    println!("uses={uses} specs={specs} parent_def={parent_def} parent_external={parent_external}");
    println!("minimum owned allocations represented: strings={strings} vecs={vecs}");
}
