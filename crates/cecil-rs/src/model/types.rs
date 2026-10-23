//! Shared data model for the `cecil` facade crate.
//!
//! Pure data definitions only: arenas handles, type descriptors, signatures,
//! and definition structs. Logic lives in sibling modules (signature codec,
//! attribute codec, reader, writer).

use std::sync::Arc;

use cecil_core::flags::*;
use cecil_core::flags::{SecurityAction, SignatureCallingConvention};
use cecil_core::Token;

/// Generates a Copy handle newtype indexing into a module arena.
macro_rules! define_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);

        impl $name {
            #[inline]
            pub fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "#{}"), self.0)
            }
        }
    };
}

define_id!(
    /// Handle to a [`TypeDefinition`] in a module's type arena.
    TypeId
);
define_id!(
    /// Handle to a [`MethodDefinition`] in a module's method arena.
    MethodId
);
define_id!(
    /// Handle to a [`FieldDefinition`] in a module's field arena.
    FieldId
);
define_id!(
    /// Handle to a [`PropertyDefinition`] in a module's property arena.
    PropertyId
);
define_id!(
    /// Handle to an [`EventDefinition`] in a module's event arena.
    EventId
);
define_id!(
    /// Handle to a [`GenericParameter`] in a module's generic parameter arena.
    GenericParamId
);

/// Four-part assembly version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, build: u16, revision: u16) -> Self {
        Version { major, minor, build, revision }
    }

    /// Parses `major[.minor[.build[.revision]]]`; missing parts default to 0.
    pub fn parse(s: &str) -> Option<Version> {
        let mut it = s.split('.');
        let mut next = || it.next()?.trim().parse::<u16>().ok();
        let major = next()?;
        let minor = next().unwrap_or(0);
        let build = next().unwrap_or(0);
        let revision = next().unwrap_or(0);
        Some(Version::new(major, minor, build, revision))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.major, self.minor, self.build, self.revision)
    }
}

/// Universal type reference used everywhere a CLR type appears (signatures,
/// base types, interfaces, attribute arguments, exception handlers).
///
/// Recursive children are `Arc`-shared: TypeSpec rows that reference other
/// rows (DAG-shaped generics) share subtrees instead of fully expanding
/// them, so memory grows linearly with the image rather than exponentially
/// with reference depth. Clones are shallow (refcount bumps). `Arc` over
/// `Rc` keeps `Module` Send+Sync for the static stores in `resolution.rs`
/// and `winrt.rs`.
#[derive(Debug, Clone)]
pub enum TypeDesc {
    /// A type defined in this module.
    Def(TypeId),
    /// A reference to a type in another scope (`TypeRef` row equivalent).
    External(Arc<ExternalType>),
    /// Zero-based single-dimension array with no bounds (`SZARRAY`).
    SzArray(Arc<TypeDesc>),
    /// Multi-dimensional array with optional sizes and lower bounds.
    Array {
        element: Arc<TypeDesc>,
        /// Upper-bound sizes per dimension (empty when unspecified).
        sizes: Vec<i32>,
        /// Lower bounds per dimension (empty when unspecified).
        lobounds: Vec<i32>,
    },
    Ptr(Arc<TypeDesc>),
    ByRef(Arc<TypeDesc>),
    Pinned(Arc<TypeDesc>),
    /// Instantiated generic type (`GENERICINST`).
    GenericInstance {
        definition: Arc<TypeDesc>,
        /// The slice and its children are shared so cloning an instantiation
        /// requires one reference count update regardless of its arity.
        arguments: Arc<[Arc<TypeDesc>]>,
    },
    /// Type generic parameter of an owning type or method.
    Var(u16),
    /// Method generic parameter.
    MVar(u16),
    /// Function pointer with the given method signature.
    FnPtr(Arc<MethodSignature>),
    /// Custom modifier (`CMOD_REQD`/`CMOD_OPT`) applied to `unmodified`.
    CMod {
        required: bool,
        modifier: Arc<TypeDesc>,
        unmodified: Arc<TypeDesc>,
    },
    /// `SENTINEL` marker for vararg call sites.
    Sentinel,
    /// `TYPEDBYREF`.
    TypedByRef,
    /// `INTERNAL` type with format-qualified name (rare).
    Internal(Arc<str>),
}

/// Reference to a type outside this module, possibly nested.
#[derive(Debug, Clone)]
pub struct ExternalType {
    pub namespace: String,
    pub name: String,
    /// Parent chain for nested external types (innermost last).
    pub nesting: Vec<Arc<ExternalType>>,
    pub scope: ScopeRef,
}

/// Compare recursive type graphs iteratively. Clones of read-side TypeSpec
/// DAGs share Arc children; recursive derived equality would revisit the same
/// subtree exponentially even for an unchanged mixed-mode snapshot.
fn type_graph_equal<'a>(first: TypeComparison<'a>) -> bool {
    use std::collections::HashSet;
    let mut work = vec![first];
    let mut seen = HashSet::new();
    while let Some(pair) = work.pop() {
        match pair {
            TypeComparison::Type(a, b) => {
                if std::ptr::eq(a, b) {
                    continue;
                }
                if !seen.insert((0u8, a as *const TypeDesc as usize, b as *const TypeDesc as usize))
                {
                    continue;
                }
                match (a, b) {
                    (TypeDesc::Def(a), TypeDesc::Def(b)) if a == b => {}
                    (TypeDesc::External(a), TypeDesc::External(b)) => {
                        work.push(TypeComparison::External(a, b))
                    }
                    (TypeDesc::SzArray(a), TypeDesc::SzArray(b))
                    | (TypeDesc::Ptr(a), TypeDesc::Ptr(b))
                    | (TypeDesc::ByRef(a), TypeDesc::ByRef(b))
                    | (TypeDesc::Pinned(a), TypeDesc::Pinned(b)) => {
                        work.push(TypeComparison::Type(a, b))
                    }
                    (
                        TypeDesc::Array { element: a, sizes: sa, lobounds: la },
                        TypeDesc::Array { element: b, sizes: sb, lobounds: lb },
                    ) if sa == sb && la == lb => work.push(TypeComparison::Type(a, b)),
                    (
                        TypeDesc::GenericInstance { definition: a, arguments: aa },
                        TypeDesc::GenericInstance { definition: b, arguments: ab },
                    ) if aa.len() == ab.len() => {
                        work.push(TypeComparison::Type(a, b));
                        for (a, b) in aa.iter().zip(ab.iter()) {
                            work.push(TypeComparison::Type(a, b));
                        }
                    }
                    (TypeDesc::Var(a), TypeDesc::Var(b))
                    | (TypeDesc::MVar(a), TypeDesc::MVar(b))
                        if a == b => {}
                    (TypeDesc::FnPtr(a), TypeDesc::FnPtr(b)) => {
                        work.push(TypeComparison::Signature(a, b))
                    }
                    (
                        TypeDesc::CMod { required: a, modifier: ma, unmodified: ua },
                        TypeDesc::CMod { required: b, modifier: mb, unmodified: ub },
                    ) if a == b => {
                        work.push(TypeComparison::Type(ma, mb));
                        work.push(TypeComparison::Type(ua, ub));
                    }
                    (TypeDesc::Sentinel, TypeDesc::Sentinel)
                    | (TypeDesc::TypedByRef, TypeDesc::TypedByRef) => {}
                    (TypeDesc::Internal(a), TypeDesc::Internal(b)) if a == b => {}
                    _ => return false,
                }
            }
            TypeComparison::External(a, b) => {
                if std::ptr::eq(a, b) {
                    continue;
                }
                if !seen.insert((
                    1u8,
                    a as *const ExternalType as usize,
                    b as *const ExternalType as usize,
                )) {
                    continue;
                }
                if a.name != b.name
                    || a.namespace != b.namespace
                    || a.nesting.len() != b.nesting.len()
                {
                    return false;
                }
                match (&a.scope, &b.scope) {
                    (ScopeRef::Assembly(a), ScopeRef::Assembly(b))
                        if Arc::ptr_eq(a, b) || a == b => {}
                    (ScopeRef::Assembly(_), ScopeRef::Assembly(_)) => return false,
                    (a, b) if a == b => {}
                    _ => return false,
                }
                for (a, b) in a.nesting.iter().zip(&b.nesting) {
                    work.push(TypeComparison::External(a, b));
                }
            }
            TypeComparison::Signature(a, b) => {
                if std::ptr::eq(a, b) {
                    continue;
                }
                if !seen.insert((
                    2u8,
                    a as *const MethodSignature as usize,
                    b as *const MethodSignature as usize,
                )) {
                    continue;
                }
                if a.has_this != b.has_this
                    || a.explicit_this != b.explicit_this
                    || a.convention != b.convention
                    || a.generic_count != b.generic_count
                    || a.vararg_start != b.vararg_start
                    || a.parameters.len() != b.parameters.len()
                {
                    return false;
                }
                work.push(TypeComparison::Type(&a.return_type, &b.return_type));
                for (a, b) in a.parameters.iter().zip(&b.parameters) {
                    work.push(TypeComparison::Type(a, b));
                }
            }
        }
    }
    true
}

enum TypeComparison<'a> {
    Type(&'a TypeDesc, &'a TypeDesc),
    External(&'a ExternalType, &'a ExternalType),
    Signature(&'a MethodSignature, &'a MethodSignature),
}

impl PartialEq for TypeDesc {
    fn eq(&self, other: &Self) -> bool {
        type_graph_equal(TypeComparison::Type(self, other))
    }
}

impl PartialEq for ExternalType {
    fn eq(&self, other: &Self) -> bool {
        type_graph_equal(TypeComparison::External(self, other))
    }
}

/// Resolution scope of an external type.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeRef {
    /// The type is declared in this very module (used by exported-type edges).
    ThisModule,
    /// Another netmodule of this assembly (`ModuleRef`).
    OtherModule(String),
    /// Another assembly (`AssemblyRef`).
    Assembly(Arc<AssemblyNameReference>),
    /// No scope (exported-type edge case / winmd projections).
    Moduleless,
}

/// Reference to another assembly (`AssemblyRef` row equivalent).
#[derive(Debug, Clone, PartialEq)]
pub struct AssemblyNameReference {
    pub name: String,
    pub version: Version,
    pub culture: Option<String>,
    pub public_key_or_token: Vec<u8>,
    pub hash: Vec<u8>,
    pub hash_algorithm: AssemblyHashAlgorithm,
    pub attributes: AssemblyAttributes,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl AssemblyNameReference {
    pub fn new(name: &str) -> Self {
        AssemblyNameReference {
            name: name.to_string(),
            version: Version::new(0, 0, 0, 0),
            culture: None,
            public_key_or_token: Vec::new(),
            hash: Vec::new(),
            hash_algorithm: AssemblyHashAlgorithm::None,
            attributes: AssemblyAttributes::empty(),
            custom_attributes: Vec::new(),
        }
    }

    /// Full name like `System.Runtime, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a`.
    pub fn full_name(&self) -> String {
        let mut s = format!(
            "{}, Version={}, Culture={}",
            self.name,
            self.version,
            self.culture.as_deref().unwrap_or("neutral")
        );
        if !self.public_key_or_token.is_empty() {
            s.push_str(&format!(
                ", PublicKeyToken={}",
                hex_upper_or_empty(&self.public_key_or_token)
            ));
        } else {
            s.push_str(", PublicKeyToken=null");
        }
        s
    }
}

fn hex_upper_or_empty(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Method signature (ECMA-335 II 23.2.1/23.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct MethodSignature {
    pub has_this: bool,
    pub explicit_this: bool,
    pub convention: SignatureCallingConvention,
    /// Number of method generic parameters (0 unless convention is Generic).
    pub generic_count: u16,
    pub parameters: Vec<TypeDesc>,
    pub return_type: TypeDesc,
    /// Index into `parameters` where vararg parameters begin (`parameters.len()` if none).
    pub vararg_start: usize,
}

impl Default for MethodSignature {
    fn default() -> Self {
        MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: Vec::new(),
            return_type: TypeDesc::Internal(
                super::signature::shared_primitive_name(0x01).expect("void primitive"),
            ),
            vararg_start: 0,
        }
    }
}

/// Field signature: just the field type.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSignature(pub TypeDesc);

/// Property signature (ECMA-335 II 23.2.5).
#[derive(Debug, Clone, PartialEq)]
pub struct PropertySignature {
    pub has_this: bool,
    /// Parameter types (index parameters), not including the property value.
    pub parameters: Vec<TypeDesc>,
    pub property_type: TypeDesc,
}

/// Local variable slot in a resolved method body.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalVariable {
    pub index: u16,
    pub ty: TypeDesc,
    pub pinned: bool,
}

/// Class layout row data attached to a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassLayout {
    pub packing_size: i32,
    pub class_size: i32,
}

/// P/Invoke declaration on a method.
#[derive(Debug, Clone, PartialEq)]
pub struct PInvokeInfo {
    pub attributes: PInvokeAttributes,
    pub entry_point: String,
    /// Name of the target native module (`ModuleRef` name).
    pub module: String,
}

/// Method override entry (`MethodImpl` row): implemented body overrides a declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodOverride {
    pub body: MethodRef,
    pub declaration: MethodRef,
}

/// Resolved reference to a method, either local or external.
#[derive(Debug, Clone, PartialEq)]
pub enum MethodRef {
    Def(MethodId),
    External(Arc<ExternalMethod>),
    /// Generic instantiation of a method reference (`MethodSpec`).
    Spec {
        method: Arc<MethodRef>,
        arguments: Arc<[TypeDesc]>,
    },
}

/// External method reference (`MemberRef` with method signature).
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalMethod {
    pub parent: TypeDesc,
    pub name: String,
    pub signature: MethodSignature,
}

/// Resolved reference to a field, either local or external.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldRef {
    Def(FieldId),
    External(Arc<ExternalField>),
}

/// External field reference (`MemberRef` with field signature).
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalField {
    pub parent: TypeDesc,
    pub name: String,
    pub signature: FieldSignature,
}

/// A custom attribute instance: constructor reference plus raw argument blob.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomAttribute {
    pub constructor: MethodRef,
    /// Raw blob including the 0x0001 prolog (named/fixed args per ECMA II 23.3).
    pub blob: Vec<u8>,
}

/// One `InterfaceImpl` row: the implemented interface plus the custom
/// attributes parented to that row (`HasCustomAttribute` tag 0x05).
/// Mono.Cecil models this as the standalone `InterfaceImplementation` object.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceImpl {
    /// Implemented interface (`TypeOrImplDef` cell of the row).
    pub interface: TypeDesc,
    /// Custom attributes attached to this specific implementation.
    pub custom_attributes: Vec<CustomAttribute>,
}

impl From<TypeDesc> for InterfaceImpl {
    fn from(interface: TypeDesc) -> Self {
        InterfaceImpl { interface, custom_attributes: Vec::new() }
    }
}

/// One `GenericParamConstraint` row: the constraint type plus the custom
/// attributes parented to that row (`HasCustomAttribute` tag 0x0d).
/// Mono.Cecil models this as the standalone `GenericParameterConstraint`
/// object.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericParamConstraint {
    /// Constraint type (`TypeOrImplDef` cell of the row).
    pub constraint: TypeDesc,
    /// Custom attributes attached to this specific constraint.
    pub custom_attributes: Vec<CustomAttribute>,
}

impl From<TypeDesc> for GenericParamConstraint {
    fn from(constraint: TypeDesc) -> Self {
        GenericParamConstraint { constraint, custom_attributes: Vec::new() }
    }
}

/// Security declaration (`DeclSecurity` row).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityDeclaration {
    pub action: SecurityAction,
    /// Raw permission-set XML blob.
    pub blob: Vec<u8>,
}

/// Constant value stored in metadata (`Constant` row payload).
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Boolean(bool),
    Char(char),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    String(String),
    /// Null-reference default (`CLASS`/`VALUETYPE` tag with null blob).
    NullRef,
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

/// A type definition living in a module's type arena.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDefinition {
    pub namespace: String,
    pub name: String,
    pub attributes: TypeAttributes,
    pub base_type: Option<TypeDesc>,
    pub interfaces: Vec<InterfaceImpl>,
    pub declaring_type: Option<TypeId>,
    pub nested_types: Vec<TypeId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub properties: Vec<PropertyId>,
    pub events: Vec<EventId>,
    pub generic_parameters: Vec<GenericParamId>,
    pub class_layout: Option<ClassLayout>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub security_declarations: Vec<SecurityDeclaration>,
}

impl Default for TypeDefinition {
    fn default() -> Self {
        TypeDefinition {
            namespace: String::new(),
            name: String::new(),
            attributes: TypeAttributes::empty(),
            base_type: None,
            interfaces: Vec::new(),
            declaring_type: None,
            nested_types: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            properties: Vec::new(),
            events: Vec::new(),
            generic_parameters: Vec::new(),
            class_layout: None,
            custom_attributes: Vec::new(),
            security_declarations: Vec::new(),
        }
    }
}

/// A field definition.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDefinition {
    pub name: String,
    pub attributes: FieldAttributes,
    pub signature: FieldSignature,
    /// Initial data bytes referenced by the field RVA (`FIELD_RVA`).
    pub initial_value: Vec<u8>,
    pub rva: u64,
    pub marshal_info: Option<MarshalInfo>,
    pub constant: Option<ConstantValue>,
    pub offset: Option<i32>,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl Default for FieldDefinition {
    fn default() -> Self {
        FieldDefinition {
            name: String::new(),
            attributes: FieldAttributes::empty(),
            signature: FieldSignature(TypeDesc::Sentinel),
            initial_value: Vec::new(),
            rva: 0,
            marshal_info: None,
            constant: None,
            offset: None,
            custom_attributes: Vec::new(),
        }
    }
}

/// A method definition.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodDefinition {
    pub name: String,
    pub attributes: MethodAttributes,
    pub impl_attributes: MethodImplAttributes,
    pub signature: MethodSignature,
    pub parameters: Vec<Parameter>,
    pub return_parameter: Parameter,
    pub generic_parameters: Vec<GenericParamId>,
    pub declaring_type: TypeId,
    /// Present-body IL; absent for abstract/native/pinvoke methods.
    pub body: Option<ResolvedBody>,
    pub pinvoke: Option<PInvokeInfo>,
    pub overrides: Vec<MethodOverride>,
    pub constant: Option<ConstantValue>,
    pub marshal_info: Option<MarshalInfo>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub security_declarations: Vec<SecurityDeclaration>,
}

impl Default for MethodDefinition {
    fn default() -> Self {
        MethodDefinition {
            name: String::new(),
            attributes: MethodAttributes::empty(),
            impl_attributes: MethodImplAttributes::empty(),
            signature: MethodSignature::default(),
            parameters: Vec::new(),
            return_parameter: Parameter::default(),
            generic_parameters: Vec::new(),
            declaring_type: TypeId(0),
            body: None,
            pinvoke: None,
            overrides: Vec::new(),
            constant: None,
            marshal_info: None,
            custom_attributes: Vec::new(),
            security_declarations: Vec::new(),
        }
    }
}

/// A method (or return) parameter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parameter {
    pub name: String,
    pub attributes: ParameterAttributes,
    /// 0 = return parameter; otherwise 1-based position.
    pub sequence: u16,
    pub marshal_info: Option<MarshalInfo>,
    pub constant: Option<ConstantValue>,
    pub custom_attributes: Vec<CustomAttribute>,
}

/// A property definition.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyDefinition {
    pub name: String,
    pub attributes: PropertyAttributes,
    pub signature: PropertySignature,
    pub get_method: Option<MethodId>,
    pub set_method: Option<MethodId>,
    pub other_methods: Vec<MethodId>,
    pub constant: Option<ConstantValue>,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl Default for PropertyDefinition {
    fn default() -> Self {
        PropertyDefinition {
            name: String::new(),
            attributes: PropertyAttributes::empty(),
            signature: PropertySignature {
                has_this: false,
                parameters: Vec::new(),
                property_type: TypeDesc::Sentinel,
            },
            get_method: None,
            set_method: None,
            other_methods: Vec::new(),
            constant: None,
            custom_attributes: Vec::new(),
        }
    }
}

/// An event definition.
#[derive(Debug, Clone, PartialEq)]
pub struct EventDefinition {
    pub name: String,
    pub attributes: EventAttributes,
    /// Delegate type raised by this event (`Event.EventType` column).
    pub event_type: Option<TypeDesc>,
    pub add_on: Option<MethodId>,
    pub remove_on: Option<MethodId>,
    pub fire: Option<MethodId>,
    pub other_methods: Vec<MethodId>,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl Default for EventDefinition {
    fn default() -> Self {
        EventDefinition {
            name: String::new(),
            attributes: EventAttributes::empty(),
            event_type: None,
            add_on: None,
            remove_on: None,
            fire: None,
            other_methods: Vec::new(),
            custom_attributes: Vec::new(),
        }
    }
}

/// Owner discriminator for a generic parameter (`GenericParam.Owner` coded index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericOwner {
    Type(TypeId),
    Method(MethodId),
}

/// A generic parameter (type or method level).
#[derive(Debug, Clone, PartialEq)]
pub struct GenericParameter {
    pub name: String,
    pub attributes: GenericParameterAttributes,
    pub position: u16,
    pub owner: GenericOwner,
    pub constraints: Vec<GenericParamConstraint>,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl Default for GenericParameter {
    fn default() -> Self {
        GenericParameter {
            name: String::new(),
            attributes: GenericParameterAttributes::empty(),
            position: 0,
            owner: GenericOwner::Type(TypeId(0)),
            constraints: Vec::new(),
            custom_attributes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved IL bodies
// ---------------------------------------------------------------------------

/// Fully resolved method body owned by a [`MethodDefinition`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedBody {
    pub max_stack: u16,
    pub init_locals: bool,
    /// Original `StandAloneSig` token backing `locals` (preserved for fidelity).
    pub local_var_sig_tok: Token,
    pub locals: Vec<LocalVariable>,
    pub instructions: Vec<RInstruction>,
    pub exception_handlers: Vec<ExceptionHandlerIL>,
}

/// One decoded instruction with resolved operand.
#[derive(Debug, Clone, PartialEq)]
pub struct RInstruction {
    pub offset: i32,
    pub opcode: cecil_cil::OpCode,
    pub operand: ROperand,
}

/// Resolved instruction operand.
#[derive(Debug, Clone, PartialEq)]
pub enum ROperand {
    None,
    Int8(i8),
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    /// Absolute target IL offset.
    Branch(i32),
    /// Absolute target IL offsets.
    Switch(Vec<i32>),
    Type(TypeDesc),
    Method(MethodRef),
    Field(FieldRef),
    /// Resolved user string.
    String(String),
    /// Unresolved `#US` heap offset (when string resolution was not possible).
    UserString(u32),
    /// Raw metadata token (kept when resolution is impossible).
    Token(Token),
    /// Typed `calli` call-site signature (Cecil `CallSite`), parsed from the
    /// instruction's `StandAloneSig` row at read time. Encoded back into a
    /// deduplicated `StandAloneSig` row on write; unparseable signatures
    /// keep the raw [`ROperand::Token`] fallback.
    CallSite(Box<MethodSignature>),
    /// RVA-targeted load (`ldind`-style raw pointer operand).
    Rva(u64),
    /// Local variable index.
    Var(u16),
}
/// Exception handling clause with IL offsets.
#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionHandlerIL {
    pub kind: ExceptionKind,
    pub try_offset: i32,
    pub try_length: i32,
    pub filter_offset: i32,
    pub handler_offset: i32,
    pub handler_length: i32,
    /// Catch type for Catch clauses.
    pub catch_type: Option<TypeDesc>,
}

/// Exception clause kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionKind {
    Catch,
    Filter,
    Finally,
    Fault,
}

// ---------------------------------------------------------------------------
// Marshal specs
// ---------------------------------------------------------------------------

/// Marshaling information (`FieldMarshal` payload).
#[derive(Debug, Clone, PartialEq)]
pub struct MarshalInfo {
    pub spec: NativeTypeSpec,
}

/// Native marshaling type specification (port of Mono.Cecil NativeType values).
#[derive(Debug, Clone, PartialEq)]
pub enum NativeTypeSpec {
    None,
    Boolean,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    LPStr,
    Int,
    UInt,
    Func,
    Array,
    Currency,
    BStr,
    LPWStr,
    LPTStr,
    ByValStr,
    ANSIBStr,
    TBStr,
    VariantBool,
    ASAny,
    FixedSysString {
        size_count: u32,
    },
    FixedArray {
        size: u32,
        element: Option<Box<NativeTypeSpec>>,
    },
    SafeArray {
        element_variant: Option<cecil_core::VariantType>,
        element_desc: Option<std::sync::Arc<TypeDesc>>,
    },
    NativeArray {
        element: Option<Box<NativeTypeSpec>>,
        /// Index of the parameter supplying the count (ECMA NATIVE_ARRAY ParamNum).
        param_num: u32,
        elem_mult: u32,
        num_elem: u32,
    },
    IUnknown,
    IDispatch,
    Struct,
    IntF {
        iid_param_index: i32,
    },
    LPStruct,
    CustomMarshaler {
        guid: [u8; 16],
        unmarshaller_ty: String,
        /// Managed marshaller type name (third SerString on the wire).
        managed_ty: String,
        cookie: String,
    },
    /// `NativeType.Max` (0x50) - appears as a nested array element sentinel.
    Max,
    Error,
}
