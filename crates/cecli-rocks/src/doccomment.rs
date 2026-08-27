//! XML documentation-comment IDs (port of `Mono.Cecil.Rocks/DocCommentId.cs`).
//!
//! Produces the identifier strings embedded in `<member name="...">` entries
//! of XML documentation files, e.g. `M:System.String.Length`, `T:Ns.Foo`2`,
//! `F:Ns.X.q`. The port keeps the C# behavior exactly, including
//!
//! * nested types joined with `.` (`T:Ns.Outer.Inner`);
//! * arity suffixes kept in definition position and stripped + brace-wrapped
//!   arguments in instantiation position (`GenericType`2` vs.
//!   `GenericType{System.Int32,Ns.K}`);
//! * type/method generic parameters spelled `` `N `` / ``` ``N ```;
//! * multi-dimensional array dimensions `[lower:size-1]`, vectors `[]`,
//!   by-ref `@`, pointers `*`, custom modifiers `!`/`|`;
//! * member names with `.`, `<`, `>` escaped to `#`, `{`, `}` so explicit
//!   interface implementations render as `N#IX{N#KVP{...}}#IXA`;
//! * conversion operators (`op_Explicit`/`op_Implicit`) appending
//!   `~ReturnType`.
//!
//! Ordinary operators keep their raw metadata names: the source emits
//! `M:N.X.op_Addition(N.X,N.X)` - there is no `Add` renaming anywhere in
//! `DocCommentId.cs`.
//!
//! Two total-function deviations from the C# (which throws): a generic
//! instance whose element is itself an instance renders recursively instead
//! of raising `NotSupportedException`, and an array whose rank cannot be
//! recovered prints a single dimension.

use cecli::model::types::{
    EventId, ExternalType, FieldId, MethodDefinition, MethodId, PropertyId, TypeDesc, TypeId,
};
use cecli::module_def::Module;
use cecli_core::flags::MethodAttributes;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Documentation id of a type (`T:Ns.Foo`2`). Only [`TypeDesc::Def`] /
/// [`TypeDesc::External`] carry identity; other shapes render like signature
/// spellings through the shared writer.
pub fn type_doc_id(ty: &TypeDesc, m: &Module) -> String {
    let mut out = String::from("T:");
    write_definition_full_name(&mut out, ty, m);
    out
}

/// Documentation id of a method:
/// `M:Ns.Type.Name``1(ParamTypes)~ReturnType?`.
pub fn method_doc_id(meth: MethodId, m: &Module) -> String {
    let meth = m.method_def(meth);
    write_method_doc_id(meth, m)
}

/// Documentation id of a field: `F:Ns.Type.Name`.
pub fn field_doc_id(field: FieldId, m: &Module) -> String {
    let def = m.field_def(field);
    let mut out = String::new();
    match find_owner(m, |t| t.fields.contains(&field)) {
        Some(owner) => write_definition(&mut out, 'F', &owner, &def.name, m),
        None => {
            // Orphan arena entry: degrade to the bare escaped item name.
            out.push('F');
            out.push(':');
            write_item_name(&mut out, &def.name);
        }
    }
    out
}

/// Documentation id of a property: `P:Ns.Type.Name(IndexerParamTypes)`.
pub fn property_doc_id(prop: PropertyId, m: &Module) -> String {
    let def = m.property_def(prop);
    let mut out = String::new();
    match find_owner(m, |t| t.properties.contains(&prop)) {
        Some(owner) => write_definition(&mut out, 'P', &owner, &def.name, m),
        None => {
            out.push('P');
            out.push(':');
            write_item_name(&mut out, &def.name);
        }
    }
    if !def.signature.parameters.is_empty() {
        write_parameter_types(&mut out, &def.signature.parameters, m);
    }
    out
}

/// Documentation id of an event: `E:Ns.Type.Name`.
pub fn event_doc_id(ev: EventId, m: &Module) -> String {
    let def = m.event_def(ev);
    let mut out = String::new();
    match find_owner(m, |t| t.events.contains(&ev)) {
        Some(owner) => write_definition(&mut out, 'E', &owner, &def.name, m),
        None => {
            out.push('E');
            out.push(':');
            write_item_name(&mut out, &def.name);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Shared writer state (C# GenericTypeOptions)
// ---------------------------------------------------------------------------

/// Tracks argument position while printing instantiated types; for nested
/// instantiations each nesting level consumes its own slice of `arguments`
/// starting at `argument_index` (port of C# `GenericTypeOptions`).
#[derive(Default)]
struct GenOpts<'a> {
    is_argument: bool,
    is_nested_type: bool,
    arguments: &'a [std::sync::Arc<TypeDesc>],
    argument_index: usize,
}

impl<'a> GenOpts<'a> {
    /// Options for printing an instantiated type's element chain.
    fn argument(arguments: &'a [std::sync::Arc<TypeDesc>], is_nested_type: bool) -> Self {
        GenOpts { is_argument: true, is_nested_type, arguments, argument_index: 0 }
    }
}

// ---------------------------------------------------------------------------
// Member ids
// ---------------------------------------------------------------------------

fn write_method_doc_id(meth: &MethodDefinition, m: &Module) -> String {
    let mut out = String::new();
    write_definition(&mut out, 'M', &meth.declaring_type, &meth.name, m);

    // WriteMethod: explicit method-generic suffix ``N ...
    let generic_count = meth.generic_parameters.len();
    if generic_count > 0 {
        out.push_str("``");
        push_usize(&mut out, generic_count);
    }

    // ... parameter types ...
    if !meth.signature.parameters.is_empty() {
        write_parameter_types(&mut out, &meth.signature.parameters, m);
    }

    // ... return type for op_Explicit/op_Implicit only.
    if is_conversion_operator(meth) {
        out.push('~');
        write_definition_full_name(&mut out, &meth.signature.return_type, m);
    }
    out
}

/// `IsConversionOperator`: special-name `op_Explicit` / `op_Implicit`.
fn is_conversion_operator(meth: &MethodDefinition) -> bool {
    meth.attributes.contains(MethodAttributes::SPECIAL_NAME)
        && (meth.name == "op_Explicit" || meth.name == "op_Implicit")
}

/// `WriteParameters`: `(type,type,...)` over parameter types.
fn write_parameter_types(out: &mut String, types: &[TypeDesc], m: &Module) {
    out.push('(');
    for (i, ty) in types.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_type_signature(out, ty, m, &mut GenOpts::default());
    }
    out.push(')');
}

/// `WriteDefinition`: `<kind>:<declaring-type-full-name>.<escaped-item-name>`.
fn write_definition(out: &mut String, kind: char, declaring: &TypeId, name: &str, m: &Module) {
    out.push(kind);
    out.push(':');
    write_definition_full_name(out, &TypeDesc::Def(*declaring), m);
    out.push('.');
    write_item_name(out, name);
}

/// `WriteItemName`: `.`,`<`,`>` become `#`,`{`,`}`.
fn write_item_name(out: &mut String, name: &str) {
    for chr in name.chars() {
        match chr {
            '.' => out.push('#'),
            '<' => out.push('{'),
            '>' => out.push('}'),
            other => out.push(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Type names and signatures
// ---------------------------------------------------------------------------

/// `WriteTypeFullName(type)` with empty options: definition position, arity
/// suffixes preserved, no brace-wrapped arguments.
fn write_definition_full_name(out: &mut String, ty: &TypeDesc, m: &Module) {
    write_type_full_name(out, ty, m, &mut GenOpts::default());
}

/// `WriteTypeFullName`: declaring chain outermost-first, namespace on every
/// level that has one, arity stripped in argument position, then the generic
/// parameter braces when applicable.
fn write_type_full_name(out: &mut String, ty: &TypeDesc, m: &Module, opts: &mut GenOpts) {
    match ty {
        TypeDesc::Def(id) => {
            let chain = def_chain(*id, m);
            for (i, level) in chain.iter().enumerate() {
                let td = m.type_def(*level);
                write_chain_level(
                    out,
                    &td.namespace,
                    &td.name,
                    td.generic_parameters.len(),
                    opts,
                    m,
                );
                if i + 1 < chain.len() {
                    // Declaring levels are joined by '.' (C#: after each
                    // WriteTypeFullName(DeclaringType) recursion level).
                    out.push('.');
                }
            }
        }
        TypeDesc::External(ext) => {
            let chain = ext_chain(ext);
            for (i, level) in chain.iter().enumerate() {
                write_chain_level(
                    out,
                    &level.namespace,
                    &level.name,
                    arity_from_name(&level.name),
                    opts,
                    m,
                );
                if i + 1 < chain.len() {
                    out.push('.');
                }
            }
        }
        // Deviation: C# throws NotSupportedException for instances over
        // instances; render recursively with both argument lists.
        TypeDesc::GenericInstance { .. } => {
            write_type_signature(out, ty, m, opts);
        }
        TypeDesc::Internal(name) => out.push_str(name),
        TypeDesc::TypedByRef => out.push_str("System.TypedByRef"),
        // Container shapes reaching full-name rendering directly: unwrap one
        // layer rather than inventing syntax.
        TypeDesc::SzArray(inner)
        | TypeDesc::Ptr(inner)
        | TypeDesc::ByRef(inner)
        | TypeDesc::Pinned(inner)
        | TypeDesc::Array { element: inner, .. } => write_type_full_name(out, inner, m, opts),
        TypeDesc::Var(_)
        | TypeDesc::MVar(_)
        | TypeDesc::FnPtr(_)
        | TypeDesc::CMod { .. }
        | TypeDesc::Sentinel => write_type_signature(out, ty, m, opts),
    }
}

/// One nesting level of `WriteTypeFullName` + `WriteGenericTypeParameters`.
fn write_chain_level(
    out: &mut String,
    ns: &str,
    name: &str,
    gp_count: usize,
    opts: &mut GenOpts,
    m: &Module,
) {
    if !ns.is_empty() {
        out.push_str(ns);
        out.push('.');
    }

    let stripped;
    let name = if opts.is_argument {
        stripped = strip_arity_suffix(name);
        stripped
    } else {
        name
    };
    out.push_str(name);

    // IsGenericType && options.IsArgument: braces around this level's slice
    // of the argument list.
    if opts.is_argument && gp_count > 0 {
        out.push('{');
        if opts.is_nested_type {
            let available = opts.arguments.len().saturating_sub(opts.argument_index).min(gp_count);
            let args = &opts.arguments[opts.argument_index..opts.argument_index + available];
            opts.argument_index += gp_count;
            write_argument_list(out, args, m);
        } else {
            write_argument_list(out, opts.arguments, m);
        }
        out.push('}');
    }
}

fn write_argument_list(out: &mut String, args: &[std::sync::Arc<TypeDesc>], m: &Module) {
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_type_signature(out, arg, m, &mut GenOpts::default());
    }
}

/// `WriteTypeSignature`: shape-aware rendering per ECMA metadata type.
fn write_type_signature(out: &mut String, ty: &TypeDesc, m: &Module, _opts: &mut GenOpts) {
    match ty {
        TypeDesc::SzArray(inner) => {
            write_type_signature(out, inner, m, _opts);
            out.push_str("[]");
        }
        TypeDesc::Array { element, sizes, lobounds } => {
            write_type_signature(out, element, m, _opts);
            write_array_dimensions(out, sizes, lobounds);
        }
        TypeDesc::ByRef(inner) => {
            write_type_signature(out, inner, m, _opts);
            out.push('@');
        }
        TypeDesc::Ptr(inner) => {
            write_type_signature(out, inner, m, _opts);
            out.push('*');
        }
        TypeDesc::Pinned(inner) => write_type_signature(out, inner, m, _opts),
        TypeDesc::GenericInstance { definition, arguments } => {
            let is_nested = match definition.as_ref() {
                TypeDesc::Def(id) => m.type_def(*id).declaring_type.is_some(),
                TypeDesc::External(ext) => !ext.nesting.is_empty(),
                _ => false,
            };
            let mut sub = GenOpts::argument(arguments, is_nested);
            write_type_full_name(out, definition, m, &mut sub);
        }
        TypeDesc::Var(pos) => {
            out.push('`');
            push_u16(out, *pos);
        }
        TypeDesc::MVar(pos) => {
            out.push_str("``");
            push_u16(out, *pos);
        }
        TypeDesc::FnPtr(sig) => {
            out.push_str("=FUNC:");
            write_definition_full_name(out, &sig.return_type, m);
            if !sig.parameters.is_empty() {
                write_parameter_types(out, &sig.parameters, m);
            }
        }
        TypeDesc::CMod { required, modifier, unmodified } => {
            write_type_signature(out, unmodified, m, _opts);
            out.push(if *required { '|' } else { '!' });
            write_type_signature(out, modifier, m, _opts);
        }
        TypeDesc::Internal(name) => out.push_str(name),
        TypeDesc::TypedByRef => out.push_str("System.TypedByRef"),
        TypeDesc::Sentinel => {}
        TypeDesc::Def(_) | TypeDesc::External(_) => write_definition_full_name(out, ty, m),
    }
}

/// `WriteArrayTypeSignature`. The model stores ECMA sizes (element counts)
/// and lower bounds; Mono.Cecil derives `UpperBound = size + lower - 1` and
/// writes `upper - (lower + 1)` = `size - 2`. Rank is the larger bound-vector
/// length (one dimension when neither was recorded).
fn write_array_dimensions(out: &mut String, sizes: &[i32], lobounds: &[i32]) {
    let rank = sizes.len().max(lobounds.len()).max(1);
    out.push('[');
    for dim in 0..rank {
        if dim > 0 {
            out.push(',');
        }
        if let Some(&lo) = lobounds.get(dim) {
            out.push_str(&lo.to_string());
        }
        out.push(':');
        if let Some(&size) = sizes.get(dim) {
            out.push_str(&(size - 2).to_string());
        }
    }
    out.push(']');
}

// ---------------------------------------------------------------------------
// Navigation helpers over module arenas
// ---------------------------------------------------------------------------

/// Declaring chain of a defined type, outermost first (includes `id` itself).
fn def_chain(id: TypeId, m: &Module) -> Vec<TypeId> {
    let mut rev = Vec::new();
    let mut cur = Some(id);
    while let Some(cid) = cur {
        rev.push(cid);
        cur = m.type_def(cid).declaring_type;
    }
    rev.reverse();
    rev
}

/// Ancestor chain of an external type, outermost first (includes the leaf).
fn ext_chain(ext: &ExternalType) -> Vec<&ExternalType> {
    let mut chain: Vec<&ExternalType> = ext.nesting.iter().map(|b| b.as_ref()).collect();
    chain.push(ext);
    chain
}

/// Finds the arena owner of a field/property/event by scanning the type
/// arena in row order (these definitions carry no back-pointer).
fn find_owner(
    m: &Module,
    owned_by: impl Fn(&cecli::model::types::TypeDefinition) -> bool,
) -> Option<TypeId> {
    m.types.iter().position(owned_by).map(|idx| TypeId(idx as u32))
}

/// Strips the trailing `` `N `` arity suffix from a generic type name.
fn strip_arity_suffix(name: &str) -> &str {
    match name.rfind('`') {
        Some(idx) if idx > 0 => &name[..idx],
        _ => name,
    }
}

/// Number of trailing digits after the last backtick (generic arity encoded
/// in the name - external references carry no separate parameter list).
fn arity_from_name(name: &str) -> usize {
    match name.rfind('`') {
        Some(idx) => name[idx + 1..].parse().unwrap_or(0),
        None => 0,
    }
}

fn push_usize(out: &mut String, value: usize) {
    out.push_str(&value.to_string());
}

fn push_u16(out: &mut String, value: u16) {
    out.push_str(&value.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use cecli::model::types::{
        EventDefinition, FieldDefinition, FieldSignature, MethodSignature, PropertyDefinition,
        PropertySignature, ScopeRef, TypeDefinition,
    };
    use cecli_core::flags::{
        EventAttributes, FieldAttributes, MethodAttributes, SignatureCallingConvention,
    };

    fn ext(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.into(),
            name: name.into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        }))
    }

    /// Nested external leaf: parents outermost-first under `nesting`.
    fn nested_ext(ns: &str, parents: &[&str], leaf: &str) -> TypeDesc {
        let mut current = ExternalType {
            namespace: ns.into(),
            name: parents[0].into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        };
        for parent in &parents[1..] {
            current = ExternalType {
                namespace: String::new(),
                name: (*parent).into(),
                nesting: vec![Box::new(current)],
                scope: ScopeRef::ThisModule,
            };
        }
        TypeDesc::External(Box::new(ExternalType {
            namespace: String::new(),
            name: leaf.into(),
            nesting: vec![Box::new(current)],
            scope: ScopeRef::ThisModule,
        }))
    }

    fn int32() -> TypeDesc {
        ext("System", "Int32")
    }

    fn sig(params: Vec<TypeDesc>, ret: TypeDesc) -> MethodSignature {
        MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: params,
            return_type: ret,
            vararg_start: 0,
        }
    }

    #[test]
    fn type_ids() {
        let mut m = Module::default();
        let x = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "X".into(),
            ..Default::default()
        });
        let inner = m.add_type(TypeDefinition {
            namespace: String::new(),
            name: "Nested".into(),
            declaring_type: Some(x),
            ..Default::default()
        });
        assert_eq!(type_doc_id(&TypeDesc::Def(x), &m), "T:N.X");
        assert_eq!(type_doc_id(&TypeDesc::Def(inner), &m), "T:N.X.Nested");

        // Generic arity survives in definition position.
        let foo = m.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Foo`2".into(),
            ..Default::default()
        });
        assert_eq!(type_doc_id(&TypeDesc::Def(foo), &m), "T:Ns.Foo`2");

        // External nested chain.
        assert_eq!(
            type_doc_id(&nested_ext("N", &["GenericType`1"], "NestedType"), &m),
            "T:N.GenericType`1.NestedType"
        );
    }

    #[test]
    fn method_and_field_and_event_ids() {
        let mut m = Module::default();
        let x = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "X".into(),
            ..Default::default()
        });

        let q = m.add_field(
            x,
            FieldDefinition {
                name: "q".into(),
                attributes: FieldAttributes::empty(),
                signature: FieldSignature(int32()),
                ..Default::default()
            },
        );
        assert_eq!(field_doc_id(q, &m), "F:N.X.q");

        let d = m.add_event(
            x,
            EventDefinition {
                name: "d".into(),
                attributes: EventAttributes::empty(),
                ..Default::default()
            },
        );
        assert_eq!(event_doc_id(d, &m), "E:N.X.d");

        let f = m.add_method(
            x,
            cecli::model::types::MethodDefinition { name: "f".into(), ..Default::default() },
        );
        assert_eq!(method_doc_id(f, &m), "M:N.X.f");

        // ByRef parameters append '@'.
        let bb = m.add_method(
            x,
            cecli::model::types::MethodDefinition {
                name: "bb".into(),
                signature: sig(
                    vec![ext("System", "String"), TypeDesc::ByRef(std::sync::Arc::new(int32()))],
                    TypeDesc::Internal("void".into()),
                ),
                ..Default::default()
            },
        );
        assert_eq!(method_doc_id(bb, &m), "M:N.X.bb(System.String,System.Int32@)");

        // Arrays: vector `[]`, md-array with zero lower bounds `[0:,0:]`.
        let gg = m.add_method(
            x,
            cecli::model::types::MethodDefinition {
                name: "gg".into(),
                signature: sig(
                    vec![
                        TypeDesc::SzArray(std::sync::Arc::new(ext("System", "Int16"))),
                        TypeDesc::Array {
                            element: std::sync::Arc::new(int32()),
                            sizes: vec![],
                            lobounds: vec![0, 0],
                        },
                    ],
                    TypeDesc::Internal("void".into()),
                ),
                ..Default::default()
            },
        );
        assert_eq!(method_doc_id(gg, &m), "M:N.X.gg(System.Int16[],System.Int32[0:,0:])");
    }

    #[test]
    fn operator_addition_keeps_metadata_name() {
        let mut m = Module::default();
        let x = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "X".into(),
            ..Default::default()
        });
        let xd = TypeDesc::Def(x);
        let op = m.add_method(
            x,
            cecli::model::types::MethodDefinition {
                name: "op_Addition".into(),
                attributes: MethodAttributes::SPECIAL_NAME | MethodAttributes::STATIC,
                signature: sig(vec![xd.clone(), xd], TypeDesc::Def(x)),
                ..Default::default()
            },
        );
        // No 'Add' mapping exists in DocCommentId.cs: raw operator name only.
        assert_eq!(method_doc_id(op, &m), "M:N.X.op_Addition(N.X,N.X)");
    }

    #[test]
    fn conversion_operator_appends_return_type() {
        let mut m = Module::default();
        let x = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "X".into(),
            ..Default::default()
        });
        let op = m.add_method(
            x,
            cecli::model::types::MethodDefinition {
                name: "op_Explicit".into(),
                attributes: MethodAttributes::SPECIAL_NAME | MethodAttributes::STATIC,
                signature: sig(vec![TypeDesc::Def(x)], int32()),
                ..Default::default()
            },
        );
        assert_eq!(method_doc_id(op, &m), "M:N.X.op_Explicit(N.X)~System.Int32");
    }

    #[test]
    fn property_ids_including_indexer() {
        let mut m = Module::default();
        let x = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "X".into(),
            ..Default::default()
        });
        let prop = m.add_property(
            x,
            PropertyDefinition {
                name: "prop".into(),
                signature: PropertySignature {
                    has_this: false,
                    parameters: vec![],
                    property_type: int32(),
                },
                ..Default::default()
            },
        );
        assert_eq!(property_doc_id(prop, &m), "P:N.X.prop");

        let indexer = m.add_property(
            x,
            PropertyDefinition {
                name: "Item".into(),
                signature: PropertySignature {
                    has_this: false,
                    parameters: vec![ext("System", "String")],
                    property_type: int32(),
                },
                ..Default::default()
            },
        );
        assert_eq!(property_doc_id(indexer, &m), "P:N.X.Item(System.String)");
    }

    #[test]
    fn generic_method_with_nested_generic_instance_parameter() {
        let mut m = Module::default();
        let owner = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "GenericMethod".into(),
            ..Default::default()
        });

        // void WithNestedType<T>(GenericType<T>.NestedType)
        let meth = m.add_method(
            owner,
            cecli::model::types::MethodDefinition {
                name: "WithNestedType".into(),
                signature: sig(
                    vec![
                        // Leaf NestedType whose parent GenericType`1 lives in N.
                        nested_ext("N", &["GenericType`1"], "NestedType"),
                    ],
                    TypeDesc::Internal("void".into()),
                ),
                ..Default::default()
            },
        );
        m.method_mut(meth).unwrap().generic_parameters.push(cecli::model::types::GenericParamId(0));

        // Instantiate GenericType<T>.NestedType over the method var ``0:
        // arity stripped from the element name, braces carry the argument.
        let param = TypeDesc::GenericInstance {
            definition: std::sync::Arc::new(nested_ext("N", &["GenericType`1"], "NestedType")),
            arguments: vec![std::sync::Arc::new(TypeDesc::MVar(0))],
        };
        m.method_mut(meth).unwrap().signature.parameters = vec![param];
        assert_eq!(
            method_doc_id(meth, &m),
            "M:N.GenericMethod.WithNestedType``1(N.GenericType{``0}.NestedType)"
        );
    }
}
