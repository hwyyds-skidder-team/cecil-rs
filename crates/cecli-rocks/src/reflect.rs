//! Reflection-style extension traits over the frozen `cecli` object model.
//!
//! Port of `rocks/Mono.Cecil.Rocks/{ModuleDefinitionRocks, TypeDefinitionRocks,
//! MethodDefinitionRocks, TypeReferenceRocks, ParameterReferenceRocks,
//! SecurityDeclarationRocks}.cs`, reshaped for the arena-based model: Cecil's
//! `this` receiver becomes a copyable handle ([`TypeId`] / [`MethodId`]) or a
//! value type plus an explicit `&Module` context, because handles alone cannot
//! reach arena data.

use cecli::model::security::{decode_security_xml, encode_security_xml};
use cecli::model::types::{
    ExternalType, MethodDefinition, MethodId, MethodSignature, Parameter, RInstruction, ScopeRef,
    SecurityDeclaration, TypeDesc, TypeId,
};
use cecli::module_def::Module;
use cecli_core::flags::{FieldAttributes, MethodAttributes, SecurityAction};
use cecli_core::{Error, Result};

// ---------------------------------------------------------------------------
// ModuleDefinitionRocks
// ---------------------------------------------------------------------------

/// Port of `ModuleDefinitionRocks.cs`.
pub trait ModuleDefinitionRocks {
    /// All types reachable from this module, in the exact order Cecil's
    /// `GetTypes` (exposed as `GetAllTypes`) yields them: a pre-order
    /// depth-first walk where each declaring type comes *first* and its
    /// nested descendants follow recursively; top-level roots are visited in
    /// arena order.
    ///
    /// Divergence from Cecil: `ModuleDefinition.Types` always starts with the
    /// `<Module>` pseudo-row, so Cecil's enumeration includes it. This arena
    /// stores only real `TypeDef` rows — there is no `<Module>` pseudo-row —
    /// hence none is yielded.
    fn get_all_types(&self) -> Vec<TypeId>;

    /// Finds a top-level type by namespace and simple name with an exact
    /// generic-arity requirement (Cecil matches ``Name`N`` spellings by
    /// arity). The stored name may carry a `` `N `` suffix; both sides are
    /// compared without it.
    fn get_type_with_generics(&self, ns: &str, name: &str, arity: usize) -> Option<TypeId>;
}

/// Pre-order depth-first walk: the type itself first, then each nested
/// subtree recursively (Cecil `ModuleDefinition.GetTypes`).
fn collect_types_preorder(m: &Module, id: TypeId, out: &mut Vec<TypeId>) {
    out.push(id);
    let nested = &m.types[id.index()].nested_types;
    for child in nested.iter().copied() {
        collect_types_preorder(m, child, out);
    }
}

/// Strips a trailing generic-arity suffix (`` `2 ``) from a metadata name.
fn strip_arity(name: &str) -> &str {
    match name.rfind('`') {
        Some(i) => {
            let digits = &name[i + 1..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                &name[..i]
            } else {
                name
            }
        }
        None => name,
    }
}

impl ModuleDefinitionRocks for Module {
    fn get_all_types(&self) -> Vec<TypeId> {
        let mut out = Vec::new();
        for i in 0..self.types.len() {
            let id = TypeId(i as u32);
            if self.types[i].declaring_type.is_none() {
                collect_types_preorder(self, id, &mut out);
            }
        }
        out
    }

    fn get_type_with_generics(&self, ns: &str, name: &str, arity: usize) -> Option<TypeId> {
        let wanted = strip_arity(name);
        self.types
            .iter()
            .position(|td| {
                td.declaring_type.is_none()
                    && td.namespace == ns
                    && strip_arity(&td.name) == wanted
                    && td.generic_parameters.len() == arity
            })
            .map(|i| TypeId(i as u32))
    }
}

// ---------------------------------------------------------------------------
// TypeDefinitionRocks
// ---------------------------------------------------------------------------

/// Port of `TypeDefinitionRocks.cs`.
pub trait TypeDefinitionRocks {
    /// Methods with exactly the given simple name, in declaration order.
    fn get_methods_named(&self, m: &Module, name: &str) -> Vec<MethodId>;

    /// Directly nested types, in declaration order.
    fn get_nested_types(&self, m: &Module) -> Vec<TypeId>;

    /// Constructors: `.ctor` / `.cctor` rows carrying both SPECIAL_NAME and
    /// RTSPECIAL_NAME (the ECMA constructor marker pair), in declaration
    /// order.
    fn get_constructors(&self, m: &Module) -> Vec<MethodId>;

    /// Non-constructor methods, in declaration order.
    fn get_methods(&self, m: &Module) -> Vec<MethodId>;

    /// The static constructor: first constructor that is static (Cecil picks
    /// it from [`Self::get_constructors`]; real `.cctor` rows carry
    /// SPECIAL_NAME | RTSPECIAL_NAME | STATIC).
    fn get_static_constructor(&self, m: &Module) -> Option<MethodId>;

    /// An accessible instance `.ctor`: instance-level and public-ish visibility
    /// (`PUBLIC`, `FAMILY`, or `FAM_OR_ASSEM`; private/assembly-only
    /// constructors are skipped — this helper has no C# counterpart and
    /// encodes the common "can I new this up?" expectation).
    fn get_default_constructor(&self, m: &Module) -> Option<MethodId>;

    /// Port of `GetEnumUnderlyingType` (Cecil keeps the helper in `Mixin`):
    /// the type of the first non-static field, which carries an enum's value.
    /// Errors when the type declares no instance field — unlike Cecil this
    /// helper does not pre-verify `IsEnum`; the instance-field scan alone
    /// defines the result.
    fn get_enum_underlying_type(&self, m: &Module) -> Result<TypeDesc>;

    /// Builds a `GENERICINST` over this type. Fails unless `args.len()`
    /// matches the declared generic-parameter count.
    fn make_generic_instance(&self, m: &Module, args: Vec<TypeDesc>) -> Result<TypeDesc>;
}

fn is_constructor(md: &MethodDefinition) -> bool {
    md.attributes.contains(MethodAttributes::SPECIAL_NAME | MethodAttributes::RTSPECIAL_NAME)
        && (md.name == ".ctor" || md.name == ".cctor")
}

impl TypeDefinitionRocks for TypeId {
    fn get_methods_named(&self, m: &Module, name: &str) -> Vec<MethodId> {
        m.types[self.index()]
            .methods
            .iter()
            .copied()
            .filter(|mid| m.methods[mid.index()].name == name)
            .collect()
    }

    fn get_nested_types(&self, m: &Module) -> Vec<TypeId> {
        m.types[self.index()].nested_types.clone()
    }

    fn get_constructors(&self, m: &Module) -> Vec<MethodId> {
        m.types[self.index()]
            .methods
            .iter()
            .copied()
            .filter(|mid| is_constructor(&m.methods[mid.index()]))
            .collect()
    }

    fn get_methods(&self, m: &Module) -> Vec<MethodId> {
        m.types[self.index()]
            .methods
            .iter()
            .copied()
            .filter(|mid| !is_constructor(&m.methods[mid.index()]))
            .collect()
    }

    fn get_static_constructor(&self, m: &Module) -> Option<MethodId> {
        self.get_constructors(m)
            .into_iter()
            .find(|mid| m.methods[mid.index()].attributes.contains(MethodAttributes::STATIC))
    }

    fn get_default_constructor(&self, m: &Module) -> Option<MethodId> {
        self.get_constructors(m).into_iter().find(|mid| {
            let md = &m.methods[mid.index()];
            !md.attributes.contains(MethodAttributes::STATIC)
                && matches!(
                    md.attributes & MethodAttributes::MEMBER_ACCESS_MASK,
                    MethodAttributes::PUBLIC
                        | MethodAttributes::FAMILY
                        | MethodAttributes::FAM_OR_ASSEM
                )
        })
    }

    fn make_generic_instance(&self, m: &Module, args: Vec<TypeDesc>) -> Result<TypeDesc> {
        let td = &m.types[self.index()];
        if args.len() != td.generic_parameters.len() {
            return Err(Error::invalid_op(format!(
                "type {} expects {} generic argument(s), got {}",
                td.name,
                td.generic_parameters.len(),
                args.len()
            )));
        }
        Ok(TypeDesc::GenericInstance {
            definition: Box::new(TypeDesc::Def(*self)),
            arguments: args,
        })
    }

    fn get_enum_underlying_type(&self, m: &Module) -> Result<TypeDesc> {
        // Mixin.GetEnumUnderlyingType: the first instance field in
        // declaration order carries the enum's underlying primitive type.
        let td = &m.types[self.index()];
        for fid in &td.fields {
            let fd = &m.fields[fid.index()];
            if !fd.attributes.contains(FieldAttributes::STATIC) {
                return Ok(fd.signature.0.clone());
            }
        }
        Err(Error::argument(format!(
            "type {} declares no instance field, so it has no enum underlying type",
            td.name
        )))
    }
}

// ---------------------------------------------------------------------------
// MethodDefinitionRocks
// ---------------------------------------------------------------------------

/// Port of `MethodDefinitionRocks.cs`.
pub trait MethodDefinitionRocks {
    /// Instructions of the resolved body; empty for methods without one
    /// (abstract / pinvoke / native).
    fn body_instructions<'a>(&self, m: &'a Module) -> &'a [RInstruction];

    /// Index into the parameter list of the parameter named `name`.
    fn get_parameter(&self, m: &Module, name: &str) -> Option<usize>;

    /// Port of `GetBaseMethod`: walks same-module base types looking for the
    /// method this virtual method overrides. Non-virtual or new-slot methods
    /// return themselves. When the base-type chain leaves the module (an
    /// external base type), resolution stops and the receiver is returned:
    /// resolving across assemblies needs an assembly resolver, which this
    /// context-free trait does not have.
    fn get_base_method(&self, m: &Module) -> MethodId;

    /// Port of `GetOriginalBaseMethod`: applies [`Self::get_base_method`]
    /// until it reaches a fixpoint.
    fn get_original_base_method(&self, m: &Module) -> MethodId;
}

fn find_matching_method(m: &Module, ty: TypeId, needle: &MethodDefinition) -> Option<MethodId> {
    // MetadataResolver.GetMethod compares name plus full signature.
    m.types[ty.index()].methods.iter().copied().find(|mid| {
        let cand = &m.methods[mid.index()];
        cand.name == needle.name && cand.signature == needle.signature
    })
}

impl MethodDefinitionRocks for MethodId {
    fn body_instructions<'a>(&self, m: &'a Module) -> &'a [RInstruction] {
        match &m.methods[self.index()].body {
            Some(body) => body.instructions.as_slice(),
            None => &[],
        }
    }

    fn get_parameter(&self, m: &Module, name: &str) -> Option<usize> {
        m.methods[self.index()].parameters.iter().position(|p| p.name == name)
    }

    fn get_base_method(&self, m: &Module) -> MethodId {
        let md = &m.methods[self.index()];
        if !md.attributes.contains(MethodAttributes::VIRTUAL)
            || md.attributes.contains(MethodAttributes::NEW_SLOT)
        {
            return *self;
        }
        let mut base = m.types[md.declaring_type.index()].base_type.clone();
        while let Some(bt) = base {
            let base_id = match bt {
                TypeDesc::Def(id) => id,
                // External base type: cannot resolve without an assembly resolver.
                _ => break,
            };
            match find_matching_method(m, base_id, md) {
                Some(found) => return found,
                None => base = m.types[base_id.index()].base_type.clone(),
            }
        }
        *self
    }

    fn get_original_base_method(&self, m: &Module) -> MethodId {
        let mut current = *self;
        loop {
            let next = current.get_base_method(m);
            if next == current {
                return current;
            }
            current = next;
        }
    }
}

// ---------------------------------------------------------------------------
// TypeReferenceRocks
// ---------------------------------------------------------------------------

/// Port of `TypeReferenceRocks.cs` (`Make*` factory helpers) plus the
/// resolution / naming helpers this split of the model requires.
pub trait TypeReferenceRocks {
    /// Resolves to the defining type inside this module. Specification forms
    /// (arrays, pointers, modifiers, generic instances) delegate to their
    /// element, mirroring `TypeSpecification.Resolve`. External references
    /// cannot be resolved here without an assembly resolver.
    fn resolve_in(&self, m: &Module) -> Option<TypeId>;

    /// Cecil-style full name: `NS.Outer/Nested` for definitions,
    /// `[scope]NS.Name` for external references, `Name`2[args]` for generic
    /// instances. Generic parameters render in ILAsm notation (`!n` type var,
    /// `!!n` method var); the `_td` suffix disambiguates from any future
    /// inherent `full_name`.
    fn full_name_td(&self, m: &Module) -> String;

    /// `SZARRAY` single-dimension array over this type.
    fn make_array_type(&self) -> TypeDesc;

    /// Multi-dimensional array with `rank` dimensions. `rank == 0` is rejected
    /// like the C# overload. The frozen [`TypeDesc::Array`] carries no
    /// explicit rank field, so the rank is preserved by storing
    /// `sizes`/`lobounds` vectors of length `rank` filled with zeros (the
    /// unspecified-bounds encoding).
    fn make_array_type_ranked(&self, rank: usize) -> Result<TypeDesc>;

    /// Pointer over this type.
    fn make_pointer_type(&self) -> TypeDesc;

    /// Managed reference over this type.
    fn make_by_ref_type(&self) -> TypeDesc;

    /// Pinned local type over this type.
    fn make_pinned_type(&self) -> TypeDesc;

    /// Required custom modifier (`CMOD_REQD`) applied to this type.
    fn make_required_modifier_type(&self, modifier: TypeDesc) -> TypeDesc;

    /// Optional custom modifier (`CMOD_OPT`) applied to this type.
    fn make_optional_modifier_type(&self, modifier: TypeDesc) -> TypeDesc;

    /// Instantiated generic type over this definition. Requires at least one
    /// argument (the C# arity check needs module context; prefer
    /// [`TypeDefinitionRocks::make_generic_instance`] on a resolved handle).
    fn make_generic_instance_type(&self, args: Vec<TypeDesc>) -> Result<TypeDesc>;

    /// Vararg call-site sentinel marker.
    fn make_sentinel_type(&self) -> TypeDesc;
}

fn def_full_name(id: TypeId, m: &Module) -> String {
    let mut chain = vec![id];
    while let Some(parent) = chain.last().and_then(|cur| m.types[cur.index()].declaring_type) {
        chain.push(parent);
    }
    chain.reverse();
    let mut s = String::new();
    let outer_ns = &m.types[chain[0].index()].namespace;
    if !outer_ns.is_empty() {
        s.push_str(outer_ns);
        s.push('.');
    }
    let names: Vec<&str> = chain.iter().map(|cur| m.types[cur.index()].name.as_str()).collect();
    s.push_str(&names.join("/"));
    s
}

fn external_full_name(ext: &ExternalType, m: &Module) -> String {
    let scope = match &ext.scope {
        ScopeRef::Assembly(a) => a.name.clone(),
        ScopeRef::OtherModule(name) => name.clone(),
        ScopeRef::ThisModule => m.name.clone(),
        ScopeRef::Moduleless => String::new(),
    };
    let mut s = String::new();
    if !scope.is_empty() {
        s.push('[');
        s.push_str(&scope);
        s.push(']');
    }
    // The nesting chain stores ancestors outermost-first; the namespace of the
    // outermost type qualifies the whole nested path.
    let ns = ext
        .nesting
        .first()
        .as_ref()
        .map(|outer| outer.namespace.as_str())
        .unwrap_or(&ext.namespace);
    if !ns.is_empty() {
        s.push_str(ns);
        s.push('.');
    }
    let names: Vec<&str> = ext
        .nesting
        .iter()
        .map(|outer| outer.name.as_str())
        .chain(std::iter::once(ext.name.as_str()))
        .collect();
    s.push_str(&names.join("/"));
    s
}

fn signature_full_name(sig: &MethodSignature, m: &Module) -> String {
    let params: Vec<String> = sig.parameters.iter().map(|p| full_name(p, m)).collect();
    format!("fn({}){}", params.join(","), full_name(&sig.return_type, m))
}

fn full_name(ty: &TypeDesc, m: &Module) -> String {
    match ty {
        TypeDesc::Def(id) => def_full_name(*id, m),
        TypeDesc::External(ext) => external_full_name(ext, m),
        TypeDesc::SzArray(element) => format!("{}[]", full_name(element, m)),
        TypeDesc::Array { element, sizes, lobounds } => {
            let rank = sizes.len().max(lobounds.len());
            let inner = if rank == 0 {
                String::new()
            } else {
                (0..rank)
                    .map(|i| lobounds.get(i).map(|lo| format!("{lo}..")).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!("{}[{}]", full_name(element, m), inner)
        }
        TypeDesc::Ptr(element) => format!("{}*", full_name(element, m)),
        TypeDesc::ByRef(element) => format!("{}&", full_name(element, m)),
        TypeDesc::Pinned(element) => format!("{} pinned", full_name(element, m)),
        TypeDesc::GenericInstance { definition, arguments } => {
            let args: Vec<String> = arguments.iter().map(|a| full_name(a, m)).collect();
            format!("{}[{}]", full_name(definition, m), args.join(","))
        }
        TypeDesc::Var(n) => format!("!{n}"),
        TypeDesc::MVar(n) => format!("!!{n}"),
        TypeDesc::FnPtr(sig) => signature_full_name(sig, m),
        TypeDesc::CMod { required, modifier, unmodified } => format!(
            "{} {}({})",
            full_name(unmodified, m),
            if *required { "modreq" } else { "modopt" },
            full_name(modifier, m)
        ),
        TypeDesc::Sentinel => "SENTINEL".to_string(),
        TypeDesc::TypedByRef => "TypedReference".to_string(),
        TypeDesc::Internal(s) => s.clone(),
    }
}

impl TypeReferenceRocks for TypeDesc {
    fn resolve_in(&self, m: &Module) -> Option<TypeId> {
        match self {
            TypeDesc::Def(id) => Some(*id),
            TypeDesc::SzArray(e) | TypeDesc::Ptr(e) | TypeDesc::ByRef(e) | TypeDesc::Pinned(e) => {
                e.resolve_in(m)
            }
            TypeDesc::Array { element, .. } => element.resolve_in(m),
            TypeDesc::GenericInstance { definition, .. } => definition.resolve_in(m),
            TypeDesc::CMod { unmodified, .. } => unmodified.resolve_in(m),
            _ => None,
        }
    }

    fn full_name_td(&self, m: &Module) -> String {
        full_name(self, m)
    }

    fn make_array_type(&self) -> TypeDesc {
        TypeDesc::SzArray(Box::new(self.clone()))
    }

    fn make_array_type_ranked(&self, rank: usize) -> Result<TypeDesc> {
        if rank == 0 {
            // C# MakeArrayType(0) throws; rank-1 arrays use make_array_type.
            return Err(Error::argument("array rank must be at least 1"));
        }
        Ok(TypeDesc::Array {
            element: Box::new(self.clone()),
            // Rank-preserving encoding: one zero entry per dimension.
            sizes: vec![0; rank],
            lobounds: vec![0; rank],
        })
    }

    fn make_pointer_type(&self) -> TypeDesc {
        TypeDesc::Ptr(Box::new(self.clone()))
    }

    fn make_by_ref_type(&self) -> TypeDesc {
        TypeDesc::ByRef(Box::new(self.clone()))
    }

    fn make_pinned_type(&self) -> TypeDesc {
        TypeDesc::Pinned(Box::new(self.clone()))
    }

    fn make_required_modifier_type(&self, modifier: TypeDesc) -> TypeDesc {
        TypeDesc::CMod {
            required: true,
            modifier: Box::new(modifier),
            unmodified: Box::new(self.clone()),
        }
    }

    fn make_optional_modifier_type(&self, modifier: TypeDesc) -> TypeDesc {
        TypeDesc::CMod {
            required: false,
            modifier: Box::new(modifier),
            unmodified: Box::new(self.clone()),
        }
    }

    fn make_generic_instance_type(&self, args: Vec<TypeDesc>) -> Result<TypeDesc> {
        if args.is_empty() {
            return Err(Error::argument("generic instantiation needs arguments"));
        }
        Ok(TypeDesc::GenericInstance { definition: Box::new(self.clone()), arguments: args })
    }

    fn make_sentinel_type(&self) -> TypeDesc {
        TypeDesc::Sentinel
    }
}

// ---------------------------------------------------------------------------
// ParameterReferenceRocks
// ---------------------------------------------------------------------------

/// Port of `ParameterReferenceRocks.cs` (`GetSequence`), expressed against the
/// frozen [`Parameter`] whose `sequence` already stores the 1-based position
/// (0 = return parameter).
pub trait ParameterReferenceRocks {
    /// Zero-based index (`ParameterReference.Index`).
    fn index(&self) -> u16;

    /// One-based sequence number (`GetSequence()`); 0 for return parameters.
    fn get_sequence(&self) -> u16;
}

impl ParameterReferenceRocks for Parameter {
    fn index(&self) -> u16 {
        self.sequence.saturating_sub(1)
    }

    fn get_sequence(&self) -> u16 {
        self.sequence
    }
}

// ---------------------------------------------------------------------------
// SecurityDeclarationRocks
// (no type imports needed here)

/// Port of `SecurityDeclarationRocks.cs`, re-based on the XML codec in
/// `cecli::model::security` (the BCL `PermissionSetAttribute` machinery the C#
/// version leans on): `to_xml` normalizes either wire form (legacy UTF-16 XML
/// or binary attribute-set) to permission-set XML text; `from_xml` encodes
/// canonical XML back into the binary attribute-set blob.
pub trait SecurityDeclarationRocks {
    /// Decodes the declaration blob into its permission-set XML text.
    fn to_xml(&self) -> Result<String>;

    /// Encodes canonical permission-set XML into a declaration with action
    /// [`SecurityAction::Demand`].
    fn from_xml(xml: &str) -> Result<SecurityDeclaration>;

    /// Like [`Self::from_xml`] with an explicit security action.
    fn from_xml_with_action(xml: &str, action: SecurityAction) -> Result<SecurityDeclaration>;
}

impl SecurityDeclarationRocks for SecurityDeclaration {
    fn to_xml(&self) -> Result<String> {
        decode_security_xml(&self.blob)
    }

    fn from_xml(xml: &str) -> Result<SecurityDeclaration> {
        Self::from_xml_with_action(xml, SecurityAction::Demand)
    }

    fn from_xml_with_action(xml: &str, action: SecurityAction) -> Result<SecurityDeclaration> {
        Ok(SecurityDeclaration { action, blob: encode_security_xml(xml)? })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cecli::model::types::{
        FieldId, GenericOwner, GenericParamId, GenericParameter, TypeDefinition,
    };
    use cecli_cil::opcodes;
    use cecli_core::flags::TypeAttributes;

    fn add_type(m: &mut Module, td: TypeDefinition) -> TypeId {
        m.types.push(td);
        TypeId((m.types.len() - 1) as u32)
    }

    fn add_method(m: &mut Module, md: MethodDefinition) -> MethodId {
        m.methods.push(md);
        MethodId((m.methods.len() - 1) as u32)
    }

    fn link(m: &mut Module, parent: TypeId, child: TypeId) {
        m.types[parent.index()].nested_types.push(child);
        m.types[child.index()].declaring_type = Some(parent);
    }

    fn attach(m: &mut Module, owner: TypeId, method: MethodId) {
        m.types[owner.index()].methods.push(method);
        m.methods[method.index()].declaring_type = owner;
    }

    fn method(name: &str, attrs: MethodAttributes) -> MethodDefinition {
        MethodDefinition { name: name.to_string(), attributes: attrs, ..Default::default() }
    }

    /// Synthetic module layout:
    /// top-level `NS.Widget` (ctors + methods), top-level `System.Func\`2`
    /// (two generic parameters), and the nested chain `NS.Outer > Inner >
    /// Deeper` where both levels define a virtual `get_Score`.
    fn sample_module() -> Module {
        let mut m = Module::default();
        m.name = "sample.dll".into();

        let widget = add_type(
            &mut m,
            TypeDefinition {
                namespace: "NS".into(),
                name: "Widget".into(),
                attributes: TypeAttributes::PUBLIC,
                ..Default::default()
            },
        );
        let func = add_type(
            &mut m,
            TypeDefinition {
                namespace: "System".into(),
                name: "Func`2".into(),
                attributes: TypeAttributes::PUBLIC,
                ..Default::default()
            },
        );
        for pos in 0..2u16 {
            m.generic_parameters.push(GenericParameter {
                name: format!("T{pos}"),
                position: pos,
                owner: GenericOwner::Type(func),
                ..Default::default()
            });
            let gid = GenericParamId((m.generic_parameters.len() - 1) as u32);
            m.types[func.index()].generic_parameters.push(gid);
        }
        let deeper =
            add_type(&mut m, TypeDefinition { name: "Deeper".into(), ..Default::default() });
        let inner = add_type(&mut m, TypeDefinition { name: "Inner".into(), ..Default::default() });
        let outer = add_type(
            &mut m,
            TypeDefinition {
                namespace: "NS".into(),
                name: "Outer".into(),
                attributes: TypeAttributes::PUBLIC,
                ..Default::default()
            },
        );
        m.types[inner.index()].base_type = Some(TypeDesc::Def(outer));
        link(&mut m, outer, inner);
        link(&mut m, inner, deeper);

        // Widget members.
        let cctor = add_method(
            &mut m,
            method(
                ".cctor",
                MethodAttributes::PRIVATE
                    | MethodAttributes::STATIC
                    | MethodAttributes::SPECIAL_NAME
                    | MethodAttributes::RTSPECIAL_NAME,
            ),
        );
        attach(&mut m, widget, cctor);
        let ctor = add_method(
            &mut m,
            method(
                ".ctor",
                MethodAttributes::PUBLIC
                    | MethodAttributes::SPECIAL_NAME
                    | MethodAttributes::RTSPECIAL_NAME,
            ),
        );
        attach(&mut m, widget, ctor);
        let mut do_work = method("DoWork", MethodAttributes::PUBLIC);
        do_work.body = Some(cecli::model::types::ResolvedBody {
            instructions: vec![
                RInstruction {
                    offset: 0,
                    opcode: opcodes::NOP,
                    operand: cecli::model::types::ROperand::None,
                },
                RInstruction {
                    offset: 1,
                    opcode: opcodes::RET,
                    operand: cecli::model::types::ROperand::None,
                },
            ],
            ..Default::default()
        });
        do_work.parameters =
            vec![Parameter { name: "amount".into(), sequence: 1, ..Default::default() }];
        let dowork_id = add_method(&mut m, do_work);
        attach(&mut m, widget, dowork_id);

        // Outer declares a virtual `get_Score` (new slot); Inner re-overrides it.
        let outer_get = add_method(
            &mut m,
            method(
                "get_Score",
                MethodAttributes::PUBLIC
                    | MethodAttributes::VIRTUAL
                    | MethodAttributes::NEW_SLOT
                    | MethodAttributes::HIDE_BY_SIG,
            ),
        );
        attach(&mut m, outer, outer_get);
        let inner_get = add_method(
            &mut m,
            method(
                "get_Score",
                MethodAttributes::PUBLIC
                    | MethodAttributes::VIRTUAL
                    | MethodAttributes::HIDE_BY_SIG,
            ),
        );
        attach(&mut m, inner, inner_get);

        // Private instance ctor on Outer must not count as a default ctor.
        let private_ctor = add_method(
            &mut m,
            method(".ctor", MethodAttributes::PRIVATE | MethodAttributes::SPECIAL_NAME),
        );
        attach(&mut m, outer, private_ctor);

        m
    }

    #[test]
    fn get_all_types_yields_declaring_type_before_nested() {
        let m = sample_module();
        let ids = m.get_all_types();
        let names: Vec<&str> = ids.iter().map(|id| m.types[id.index()].name.as_str()).collect();
        // Cecil pre-order DFS: each declaring type precedes its nested
        // descendants; top-level roots follow arena order.
        assert_eq!(names, vec!["Widget", "Func`2", "Outer", "Inner", "Deeper"]);
    }

    #[test]
    fn get_type_with_generics_matches_namespace_name_and_arity() {
        let m = sample_module();
        assert_eq!(m.get_type_with_generics("System", "Func", 2), Some(TypeId(1)));
        // Backtick spelling works too.
        assert_eq!(m.get_type_with_generics("System", "Func`2", 2), Some(TypeId(1)));
        assert_eq!(m.get_type_with_generics("System", "Func", 1), None);
        assert_eq!(m.get_type_with_generics("System", "Widget", 2), None);
        assert_eq!(m.get_type_with_generics("Missing", "Func", 2), None);
        // Nested types are not reachable through the module-level lookup.
        assert_eq!(m.get_type_with_generics("", "Inner", 0), None);
    }

    #[test]
    fn get_methods_named_and_nested_and_non_ctor_views() {
        let m = sample_module();
        let widget = TypeId(0);
        let named: Vec<&str> = widget
            .get_methods_named(&m, "DoWork")
            .iter()
            .map(|mid| m.methods[mid.index()].name.as_str())
            .collect();
        assert_eq!(named, vec!["DoWork"]);
        assert!(widget.get_methods_named(&m, "nope").is_empty());

        // Non-constructor view skips both ctors.
        let plain: Vec<&str> =
            widget.get_methods(&m).iter().map(|mid| m.methods[mid.index()].name.as_str()).collect();
        assert_eq!(plain, vec!["DoWork"]);

        let outer = TypeId(4);
        assert_eq!(
            outer.get_nested_types(&m),
            vec![TypeId(3)] // Inner
        );
        assert_eq!(TypeId(3).get_nested_types(&m), vec![TypeId(2)]); // Inner > Deeper
        assert!(TypeId(2).get_nested_types(&m).is_empty()); // Deeper is a leaf
    }

    #[test]
    fn static_constructor_found_by_name_and_flags() {
        let m = sample_module();
        let cctor = TypeId(0).get_static_constructor(&m);
        let md = &m.methods[cctor.expect("static ctor").index()];
        assert_eq!(md.name, ".cctor");
        assert!(md.attributes.contains(MethodAttributes::STATIC));
        assert!(md.attributes.contains(MethodAttributes::SPECIAL_NAME));
        // Types without one yield nothing.
        assert_eq!(TypeId(4).get_static_constructor(&m), None);
    }

    #[test]
    fn default_constructor_skips_private_and_static() {
        let m = sample_module();
        let ctor = TypeId(0).get_default_constructor(&m);
        let md = &m.methods[ctor.expect("public .ctor").index()];
        assert_eq!(md.name, ".ctor");
        assert!(!md.attributes.contains(MethodAttributes::STATIC));
        // Outer only declares a PRIVATE instance ctor — and one lacking
        // RTSPECIAL_NAME is not a constructor at all, so it never shows up
        // in the ctor views either.
        assert_eq!(TypeId(4).get_default_constructor(&m), None);
        assert!(TypeId(4).get_constructors(&m).is_empty());
        let outer_plain: Vec<&str> = TypeId(4)
            .get_methods(&m)
            .iter()
            .map(|mid| m.methods[mid.index()].name.as_str())
            .collect();
        assert!(outer_plain.contains(&".ctor"));
    }

    #[test]
    fn get_enum_underlying_type_returns_first_instance_field_type() {
        let mut m = Module::default();
        let enum_ty = add_type(
            &mut m,
            TypeDefinition { namespace: "NS".into(), name: "Color".into(), ..Default::default() },
        );
        let value_field = cecli::model::types::FieldDefinition {
            name: "value__".into(),
            attributes: FieldAttributes::PUBLIC,
            signature: cecli::model::types::FieldSignature(TypeDesc::Internal("int32".into())),
            ..Default::default()
        };
        m.fields.push(value_field);
        m.types[enum_ty.index()].fields.push(FieldId((m.fields.len() - 1) as u32));
        let static_field = cecli::model::types::FieldDefinition {
            name: "Red".into(),
            attributes: FieldAttributes::PUBLIC
                | FieldAttributes::STATIC
                | FieldAttributes::LITERAL,
            signature: cecli::model::types::FieldSignature(TypeDesc::Def(enum_ty)),
            ..Default::default()
        };
        m.fields.push(static_field);
        m.types[enum_ty.index()].fields.push(FieldId((m.fields.len() - 1) as u32));

        let underlying = enum_ty
            .get_enum_underlying_type(&m)
            .expect("instance field carries the underlying type");
        assert_eq!(underlying, TypeDesc::Internal("int32".into()));

        // A type with only static fields has no underlying type.
        let empty =
            add_type(&mut m, TypeDefinition { name: "NotAnEnum".into(), ..Default::default() });
        assert!(empty.get_enum_underlying_type(&m).is_err());
    }

    #[test]
    fn make_generic_instance_checks_arity() {
        let m = sample_module();
        let func = TypeId(1);
        let string_t = string_external();
        let ok = func
            .make_generic_instance(&m, vec![string_t.clone(), string_t])
            .expect("arity matches");
        match ok {
            TypeDesc::GenericInstance { definition, arguments } => {
                assert_eq!(*definition, TypeDesc::Def(func));
                assert_eq!(arguments.len(), 2);
            }
            other => panic!("unexpected descriptor: {other:?}"),
        }
        assert!(func.make_generic_instance(&m, vec![string_external()]).is_err());
    }

    #[test]
    fn body_instructions_and_parameter_lookup() {
        let m = sample_module();
        let dowork = TypeId(0).get_methods_named(&m, "DoWork")[0];
        let code = dowork.body_instructions(&m);
        assert_eq!(code.len(), 2);
        assert_eq!(code[0].opcode.name, "nop");

        // Abstract-style member without body yields an empty slice.
        let getscore = TypeId(4).get_methods_named(&m, "get_Score")[0];
        assert!(getscore.body_instructions(&m).is_empty());

        assert_eq!(dowork.get_parameter(&m, "amount"), Some(0));
        assert_eq!(dowork.get_parameter(&m, "missing"), None);
    }

    #[test]
    fn base_method_walks_same_module_chain() {
        let m = sample_module();
        let outer_get = TypeId(4).get_methods_named(&m, "get_Score")[0];
        let inner_get = TypeId(3).get_methods_named(&m, "get_Score")[0];

        // Inner.get_Score is virtual without NewSlot: its base is Outer.get_Score.
        assert_eq!(inner_get.get_base_method(&m), outer_get);
        // Outer.get_Score is new-slot: its own base is itself.
        assert_eq!(outer_get.get_base_method(&m), outer_get);
        // Fixpoint iteration terminates immediately there.
        assert_eq!(inner_get.get_original_base_method(&m), outer_get);

        // A non-virtual method resolves to itself.
        let dowork = TypeId(0).get_methods_named(&m, "DoWork")[0];
        assert_eq!(dowork.get_base_method(&m), dowork);
    }

    fn string_external() -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "String".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(assembly_ref("mscorlib")),
        }))
    }

    fn assembly_ref(name: &str) -> cecli::model::types::AssemblyNameReference {
        cecli::model::types::AssemblyNameReference::new(name)
    }

    #[test]
    fn resolve_in_defers_specifications_to_element() {
        let m = sample_module();
        let widget = TypeId(0);
        assert_eq!(TypeDesc::Def(widget).resolve_in(&m), Some(widget));
        assert_eq!(string_external().resolve_in(&m), None);
        // SZARRAY over Def resolves through the element.
        let arr = TypeDesc::Def(widget).make_array_type();
        assert_eq!(arr.resolve_in(&m), Some(widget));
        // Generic instance over Func resolves to Func.
        let inst = TypeDesc::GenericInstance {
            definition: Box::new(TypeDesc::Def(TypeId(1))),
            arguments: vec![string_external(), string_external()],
        };
        assert_eq!(inst.resolve_in(&m), Some(TypeId(1)));
        // Unbound variables never resolve.
        assert_eq!(TypeDesc::Var(0).resolve_in(&m), None);
    }

    #[test]
    fn full_names_match_cecil_spelling() {
        let m = sample_module();
        // Nested definitions join declaring types with '/' under the outermost namespace.
        assert_eq!(TypeDesc::Def(TypeId(2)).full_name_td(&m), "NS.Outer/Inner/Deeper");
        assert_eq!(TypeDesc::Def(TypeId(0)).full_name_td(&m), "NS.Widget");
        // External references carry the scope in brackets.
        assert_eq!(string_external().full_name_td(&m), "[mscorlib]System.String");
        // Generic instances append comma-joined arguments.
        let inst = TypeDesc::GenericInstance {
            definition: Box::new(TypeDesc::Def(TypeId(1))),
            arguments: vec![string_external(), TypeDesc::Def(TypeId(0))],
        };
        assert_eq!(inst.full_name_td(&m), "System.Func`2[[mscorlib]System.String,NS.Widget]");
        // Specifications.
        assert_eq!(TypeDesc::Def(TypeId(0)).make_array_type().full_name_td(&m), "NS.Widget[]");
        assert_eq!(TypeDesc::Def(TypeId(0)).make_pointer_type().full_name_td(&m), "NS.Widget*");
        assert_eq!(TypeDesc::Def(TypeId(0)).make_by_ref_type().full_name_td(&m), "NS.Widget&");
        assert_eq!(TypeDesc::Var(0).full_name_td(&m), "!0");
        assert_eq!(TypeDesc::MVar(1).full_name_td(&m), "!!1");
    }

    #[test]
    fn make_factories_shape_descriptors() {
        let t = string_external();
        let ranked = t.make_array_type_ranked(2).expect("rank 2");
        match &ranked {
            TypeDesc::Array { element, sizes, lobounds } => {
                assert_eq!(**element, t);
                assert_eq!((sizes.len(), lobounds.len()), (2, 2));
                assert!(sizes.iter().all(|&s| s == 0) && lobounds.iter().all(|&l| l == 0));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(t.make_array_type_ranked(0).is_err());

        let modreq = t.make_required_modifier_type(string_external());
        match &modreq {
            TypeDesc::CMod { required, .. } => assert!(*required),
            other => panic!("unexpected: {other:?}"),
        }
        let pinned = t.make_pinned_type();
        assert!(matches!(pinned, TypeDesc::Pinned(_)));
        assert_eq!(t.make_sentinel_type(), TypeDesc::Sentinel);

        let inst = t.make_generic_instance_type(vec![string_external()]).unwrap();
        assert!(matches!(inst, TypeDesc::GenericInstance { .. }));
        assert!(t.make_generic_instance_type(vec![]).is_err());
    }

    #[test]
    fn parameter_sequence_helpers() {
        use cecli::model::types::Parameter;
        let ret = Parameter { sequence: 0, ..Default::default() };
        let third = Parameter { sequence: 3, ..Default::default() };
        assert_eq!(ret.index(), 0);
        assert_eq!(ret.get_sequence(), 0);
        assert_eq!(third.index(), 2);
        assert_eq!(third.get_sequence(), 3);
    }

    const CANONICAL_XML: &str = concat!(
        "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\">\r\n",
        "<IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib\" ",
        "version=\"1\" Flags=\"UnmanagedCode\"/>\r\n",
        "</PermissionSet>\r\n"
    );

    #[test]
    fn security_declaration_xml_roundtrip_via_trait() {
        let decl = SecurityDeclaration::from_xml(CANONICAL_XML).expect("encode");
        assert_eq!(decl.action, SecurityAction::Demand);
        assert_eq!(decl.blob[0], b'.');
        assert_eq!(decl.to_xml().expect("decode"), CANONICAL_XML);

        let explicit = SecurityDeclaration::from_xml_with_action(
            CANONICAL_XML,
            SecurityAction::RequestMinimum,
        )
        .expect("encode");
        assert_eq!(explicit.action, SecurityAction::RequestMinimum);
    }
}
