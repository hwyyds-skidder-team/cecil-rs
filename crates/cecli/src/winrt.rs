//! Windows Runtime projection engine.
//!
//! Full port of `Mono.Cecil/WindowsRuntimeProjections.cs` together with the
//! treatment flags from `Mono.Cecil/Treatments.cs`. The engine rewrites a
//! parsed [`Module`] between its *Windows Metadata* spelling (what a `.winmd`
//! image stores on disk) and its *projected CLR* spelling (what the .NET
//! runtime actually reflects over):
//!
//! * **Apply** ([`apply_projections`]) mirrors what Cecil's reader does while
//!   loading a winmd: virtual `System.Runtime*` assembly references are
//!   appended (and `mscorlib` is re-versioned), well-known WinRT type
//!   references are renamed to their CLR identities (`IIterable\`1` ->
//!   `IEnumerable\`1`, scoped to `System.Runtime`), `\<CLR>` implementation
//!   types are unmangled, public managed-winmd types get the `\<WinRT>`
//!   prefix, `AttributeUsageAttribute` records gain an `AllowMultiple`
//!   property, and classes implementing projected interfaces receive
//!   synthesized "redirected" methods plus un-projected interface duplicates.
//! * **Remove** ([`remove_projections`]) reverses every mutation exactly,
//!   restoring names, flags, signatures, attribute blobs and assembly
//!   references.
//!
//! # Projection bookkeeping
//!
//! Mono.Cecil hangs a `WindowsRuntimeProjection` object off every projected
//! type/method/field/reference. This crate's frozen data model has no such
//! field, so the inverse-mapping records live in a process-global store
//! keyed by the module MVID ([`Module::guid`]). Consequences:
//!
//! * modules passed here must have unique guids (real modules always do;
//!   synthetic fixtures must assign them explicitly),
//! * records exist only between the `apply` and `remove` calls; dropping
//!   them without `remove_projections` leaves a module permanently projected.
//! * Detached redirected methods remain in the method arena after
//!   [`remove_projections`] (arena slots cannot be freed without
//!   invalidating handles); they are removed from their owning type's member
//!   list, which is what the writer serializes.
//! * Interface-closure resolution (`CollectImplementedInterfaces`) walks
//!   only definitions resolvable inside the current module; references into
//!   other winmds end the traversal instead of throwing.
use cecli_core::flags::{
    AssemblyAttributes, FieldAttributes, MetadataKind, MethodAttributes, MethodImplAttributes,
    SignatureCallingConvention, TypeAttributes,
};
use cecli_core::io::ByteReader;
use cecli_core::{Error, Result};

use crate::model::substitution::substitute_signature;
use crate::model::types::{
    AssemblyNameReference, CustomAttribute, ExternalMethod, ExternalType, FieldId, FieldRef,
    MarshalInfo, MethodDefinition, MethodId, MethodOverride, MethodRef, MethodSignature,
    NativeTypeSpec, ROperand, ScopeRef, TypeDesc, TypeId, Version,
};
use crate::module_def::Module;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

/// How a [`TypeDefinition`](crate::model::types::TypeDefinition) must be treated when projecting (Treatments.cs).
///
/// Hand-rolled bitflag type: the `cecli` crate does not depend on the
/// `bitflags` crate (only `cecli-core` does).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TypeDefinitionTreatment(pub u8);

impl TypeDefinitionTreatment {
    pub const NONE: Self = Self(0x0);
    /// Low four bits select the kind-specific rewrite.
    pub const KIND_MASK: Self = Self(0xf);
    pub const NORMAL_TYPE: Self = Self(0x1);
    pub const NORMAL_ATTRIBUTE: Self = Self(0x2);
    pub const UNMANGLE_WINDOWS_RUNTIME_NAME: Self = Self(0x3);
    pub const PREFIX_WINDOWS_RUNTIME_NAME: Self = Self(0x4);
    pub const REDIRECT_TO_CLR_TYPE: Self = Self(0x5);
    pub const REDIRECT_TO_CLR_ATTRIBUTE: Self = Self(0x6);
    pub const REDIRECT_IMPLEMENTED_METHODS: Self = Self(0x7);

    pub const ABSTRACT: Self = Self(0x10);
    pub const INTERNAL: Self = Self(0x20);

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for TypeDefinitionTreatment {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for TypeDefinitionTreatment {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for TypeDefinitionTreatment {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// How a type *reference* is projected (Treatments.cs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TypeReferenceTreatment {
    #[default]
    None,
    /// `System.MulticastDelegate` re-scoped to `System.Runtime`.
    SystemDelegate,
    /// `System.Attribute` re-scoped to `System.Runtime`.
    SystemAttribute,
    /// Renamed/re-scoped through the well-known projection name table.
    UseProjectionInfo,
}

/// Method-level treatment flags (Treatments.cs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MethodDefinitionTreatment(pub u8);

impl MethodDefinitionTreatment {
    pub const NONE: Self = Self(0x0);
    pub const ABSTRACT: Self = Self(0x2);
    pub const PRIVATE: Self = Self(0x4);
    pub const PUBLIC: Self = Self(0x8);
    pub const RUNTIME: Self = Self(0x10);
    pub const INTERNAL_CALL: Self = Self(0x20);

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for MethodDefinitionTreatment {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for MethodDefinitionTreatment {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Field-level treatment flags (Treatments.cs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FieldDefinitionTreatment(pub u8);

impl FieldDefinitionTreatment {
    pub const NONE: Self = Self(0x0);
    pub const PUBLIC: Self = Self(0x1);

    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Custom-attribute-record treatment (Treatments.cs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CustomAttributeValueTreatment {
    #[default]
    None,
    AllowSingle,
    AllowMultiple,
    VersionAttribute,
    DeprecatedAttribute,
}

/// `System.AttributeTargets` flag values used when patching
/// `AttributeUsageAttribute` records.
pub mod attribute_targets {
    pub const ASSEMBLY: i32 = 0x0001;
    pub const MODULE: i32 = 0x0002;
    pub const CLASS: i32 = 0x0004;
    pub const STRUCT: i32 = 0x0008;
    pub const ENUM: i32 = 0x0010;
    pub const CONSTRUCTOR: i32 = 0x0020;
    pub const METHOD: i32 = 0x0040;
    pub const PROPERTY: i32 = 0x0080;
    pub const FIELD: i32 = 0x0100;
    pub const EVENT: i32 = 0x0200;
    pub const INTERFACE: i32 = 0x0400;
    pub const PARAMETER: i32 = 0x0800;
    pub const DELEGATE: i32 = 0x1000;
    pub const RETURN_VALUE: i32 = 0x2000;
    pub const GENERIC_PARAMETER: i32 = 0x4000;
    pub const ALL: i32 = 0x7FFF;
}

// ---------------------------------------------------------------------------
// Well-known projection name table (WindowsRuntimeProjections.Projections)
// ---------------------------------------------------------------------------

/// One row of the well-known WinRT->CLR projection name table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionInfo {
    /// Namespace the type carries inside the winmd.
    pub winrt_namespace: &'static str,
    /// Namespace the projected CLR type lives in.
    pub clr_namespace: &'static str,
    /// Name of the projected CLR type.
    pub clr_name: &'static str,
    /// Projecting assembly the CLR type is forwarded to.
    pub clr_assembly: &'static str,
    /// `true` when the WinRT type is an attribute (treated as
    /// `RedirectToClrAttribute` instead of `RedirectToClrType`).
    pub attribute: bool,
}

const fn pi(
    winrt_namespace: &'static str,
    clr_namespace: &'static str,
    clr_name: &'static str,
    clr_assembly: &'static str,
) -> ProjectionInfo {
    ProjectionInfo { winrt_namespace, clr_namespace, clr_name, clr_assembly, attribute: false }
}

const fn pia(
    winrt_namespace: &'static str,
    clr_namespace: &'static str,
    clr_name: &'static str,
    clr_assembly: &'static str,
) -> ProjectionInfo {
    ProjectionInfo { winrt_namespace, clr_namespace, clr_name, clr_assembly, attribute: true }
}

/// Well-known projection rows, verbatim from WindowsRuntimeProjections.cs,
/// in dictionary-insertion order.
pub static PROJECTIONS: &[ProjectionInfo] = &[
    pi("Windows.Foundation.Metadata", "System", "AttributeTargets", "System.Runtime"),
    pia("Windows.Foundation.Metadata", "System", "AttributeUsageAttribute", "System.Runtime"),
    pi("Windows.UI", "Windows.UI", "Color", "System.Runtime.WindowsRuntime"),
    pi(
        "Windows.UI.Xaml",
        "Windows.UI.Xaml",
        "CornerRadius",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.Foundation", "System", "DateTimeOffset", "System.Runtime"),
    pi("Windows.UI.Xaml", "Windows.UI.Xaml", "Duration", "System.Runtime.WindowsRuntime.UI.Xaml"),
    pi(
        "Windows.UI.Xaml",
        "Windows.UI.Xaml",
        "DurationType",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.Foundation", "System", "EventHandler`1", "System.Runtime"),
    pi(
        "Windows.Foundation",
        "System.Runtime.InteropServices.WindowsRuntime",
        "EventRegistrationToken",
        "System.Runtime.InteropServices.WindowsRuntime",
    ),
    pi(
        "Windows.UI.Xaml.Controls.Primitives",
        "Windows.UI.Xaml.Controls.Primitives",
        "GeneratorPosition",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.UI.Xaml", "Windows.UI.Xaml", "GridLength", "System.Runtime.WindowsRuntime.UI.Xaml"),
    pi(
        "Windows.UI.Xaml",
        "Windows.UI.Xaml",
        "GridUnitType",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.Foundation", "System", "Exception", "System.Runtime"),
    pi("Windows.UI.Xaml.Interop", "System.Collections", "IEnumerable", "System.Runtime"),
    pi("Windows.UI.Xaml.Interop", "System.Collections", "IList", "System.Runtime"),
    pi("Windows.Foundation", "System", "IDisposable", "System.Runtime"),
    pi("Windows.UI.Xaml.Input", "System.Windows.Input", "ICommand", "System.ObjectModel"),
    pi(
        "Windows.Foundation.Collections",
        "System.Collections.Generic",
        "IEnumerable`1",
        "System.Runtime",
    ),
    pi(
        "Windows.Foundation.Collections",
        "System.Collections.Generic",
        "KeyValuePair`2",
        "System.Runtime",
    ),
    pi(
        "Windows.Foundation.Collections",
        "System.Collections.Generic",
        "IReadOnlyDictionary`2",
        "System.Runtime",
    ),
    pi(
        "Windows.Foundation.Collections",
        "System.Collections.Generic",
        "IDictionary`2",
        "System.Runtime",
    ),
    pi(
        "Windows.UI.Xaml.Interop",
        "System.Collections.Specialized",
        "INotifyCollectionChanged",
        "System.ObjectModel",
    ),
    pi(
        "Windows.UI.Xaml.Data",
        "System.ComponentModel",
        "INotifyPropertyChanged",
        "System.ObjectModel",
    ),
    pi("Windows.Foundation", "System", "Nullable`1", "System.Runtime"),
    pi(
        "Windows.Foundation.Collections",
        "System.Collections.Generic",
        "IReadOnlyList`1",
        "System.Runtime",
    ),
    pi("Windows.Foundation.Collections", "System.Collections.Generic", "IList`1", "System.Runtime"),
    pi(
        "Windows.UI.Xaml.Media.Animation",
        "Windows.UI.Xaml.Media.Animation",
        "KeyTime",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi(
        "Windows.UI.Xaml.Media",
        "Windows.UI.Xaml.Media",
        "Matrix",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi(
        "Windows.UI.Xaml.Media.Media3D",
        "Windows.UI.Xaml.Media.Media3D",
        "Matrix3D",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Matrix3x2", "System.Numerics.Vectors"),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Matrix4x4", "System.Numerics.Vectors"),
    pi(
        "Windows.UI.Xaml.Interop",
        "System.Collections.Specialized",
        "NotifyCollectionChangedAction",
        "System.ObjectModel",
    ),
    pi(
        "Windows.UI.Xaml.Interop",
        "System.Collections.Specialized",
        "NotifyCollectionChangedEventArgs",
        "System.ObjectModel",
    ),
    pi(
        "Windows.UI.Xaml.Interop",
        "System.Collections.Specialized",
        "NotifyCollectionChangedEventHandler",
        "System.ObjectModel",
    ),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Plane", "System.Numerics.Vectors"),
    pi("Windows.Foundation", "Windows.Foundation", "Point", "System.Runtime.WindowsRuntime"),
    pi(
        "Windows.UI.Xaml.Data",
        "System.ComponentModel",
        "PropertyChangedEventArgs",
        "System.ObjectModel",
    ),
    pi(
        "Windows.UI.Xaml.Data",
        "System.ComponentModel",
        "PropertyChangedEventHandler",
        "System.ObjectModel",
    ),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Quaternion", "System.Numerics.Vectors"),
    pi("Windows.Foundation", "Windows.Foundation", "Rect", "System.Runtime.WindowsRuntime"),
    pi(
        "Windows.UI.Xaml.Media.Animation",
        "Windows.UI.Xaml.Media.Animation",
        "RepeatBehavior",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi(
        "Windows.UI.Xaml.Media.Animation",
        "Windows.UI.Xaml.Media.Animation",
        "RepeatBehaviorType",
        "System.Runtime.WindowsRuntime.UI.Xaml",
    ),
    pi("Windows.Foundation", "Windows.Foundation", "Size", "System.Runtime.WindowsRuntime"),
    pi("Windows.UI.Xaml", "Windows.UI.Xaml", "Thickness", "System.Runtime.WindowsRuntime.UI.Xaml"),
    pi("Windows.Foundation", "System", "TimeSpan", "System.Runtime"),
    pi("Windows.UI.Xaml.Interop", "System", "Type", "System.Runtime"),
    pi("Windows.Foundation", "System", "Uri", "System.Runtime"),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Vector2", "System.Numerics.Vectors"),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Vector3", "System.Numerics.Vectors"),
    pi("Windows.Foundation.Numerics", "System.Numerics", "Vector4", "System.Numerics.Vectors"),
];

/// The dictionary keys of the C# table (WinRT-side names), aligned 1:1 with
/// [`PROJECTIONS`].
static PROJECTION_KEYS: &[&str] = &[
    "AttributeTargets",
    "AttributeUsageAttribute",
    "Color",
    "CornerRadius",
    "DateTime",
    "Duration",
    "DurationType",
    "EventHandler`1",
    "EventRegistrationToken",
    "GeneratorPosition",
    "GridLength",
    "GridUnitType",
    "HResult",
    "IBindableIterable",
    "IBindableVector",
    "IClosable",
    "ICommand",
    "IIterable`1",
    "IKeyValuePair`2",
    "IMapView`2",
    "IMap`2",
    "INotifyCollectionChanged",
    "INotifyPropertyChanged",
    "IReference`1",
    "IVectorView`1",
    "IVector`1",
    "KeyTime",
    "Matrix",
    "Matrix3D",
    "Matrix3x2",
    "Matrix4x4",
    "NotifyCollectionChangedAction",
    "NotifyCollectionChangedEventArgs",
    "NotifyCollectionChangedEventHandler",
    "Plane",
    "Point",
    "PropertyChangedEventArgs",
    "PropertyChangedEventHandler",
    "Quaternion",
    "Rect",
    "RepeatBehavior",
    "RepeatBehaviorType",
    "Size",
    "Thickness",
    "TimeSpan",
    "TypeName",
    "Uri",
    "Vector2",
    "Vector3",
    "Vector4",
];

/// Looks up the well-known projection table by the *WinRT* (unprojected)
/// type name.
pub fn well_known_projection(name: &str) -> Option<&'static ProjectionInfo> {
    debug_assert_eq!(PROJECTIONS.len(), PROJECTION_KEYS.len());
    PROJECTION_KEYS.iter().position(|k| *k == name).map(|i| &PROJECTIONS[i])
}

// ---------------------------------------------------------------------------
// Saved-projection records
// ---------------------------------------------------------------------------

/// Original identity of a projected type reference
/// (`TypeReferenceProjection` in WindowsRuntimeProjections.cs).
#[derive(Debug, Clone)]
pub struct TypeReferenceProjection {
    pub name: String,
    pub namespace: String,
    pub scope: ScopeRef,
    pub treatment: TypeReferenceTreatment,
}

/// Original state of a projected type definition.
#[derive(Debug, Clone)]
pub struct TypeDefinitionProjection {
    pub attributes: TypeAttributes,
    pub name: String,
    pub treatment: TypeDefinitionTreatment,
    /// `(projected_interface, unprojected_interface)` pairs.
    pub redirected_interfaces: Vec<(TypeDesc, TypeDesc)>,
    /// Methods synthesised by the projection; detached again on removal.
    pub redirected_method_ids: Vec<MethodId>,
}

/// Original state of a projected method definition.
#[derive(Debug, Clone)]
pub struct MethodDefinitionProjection {
    pub attributes: MethodAttributes,
    pub impl_attributes: MethodImplAttributes,
    pub name: String,
    pub treatment: MethodDefinitionTreatment,
}

/// Original state of a projected field definition.
#[derive(Debug, Clone)]
pub struct FieldDefinitionProjection {
    pub attributes: FieldAttributes,
    pub treatment: FieldDefinitionTreatment,
}

/// Original state of a projected custom-attribute record
/// (`CustomAttributeValueProjection` plus the untouched ECMA blob).
#[derive(Debug, Clone)]
pub struct CustomAttributeValueProjection {
    /// `AttributeTargets` value of constructor argument 0 before patching.
    pub targets: i32,
    pub treatment: CustomAttributeValueTreatment,
    /// Blob exactly as read, restored verbatim on removal.
    pub original_blob: Vec<u8>,
}

#[derive(Debug, Default)]
struct ModuleProjections {
    corlib_saved_version: Option<Version>,
    virtual_refs_added: Vec<String>,
    references: HashMap<(String, String), TypeReferenceProjection>,
    types: BTreeMap<u32, TypeDefinitionProjection>,
    methods: BTreeMap<u32, MethodDefinitionProjection>,
    fields: BTreeMap<u32, FieldDefinitionProjection>,
    /// Keyed by `(TypeId, index into TypeDefinition::custom_attributes)`.
    attributes: BTreeMap<(u32, u32), CustomAttributeValueProjection>,
    /// Arena ids of methods synthesised by `RedirectImplementedMethods`.
    added_methods: HashSet<u32>,
}

/// Process-global inverse-mapping store, keyed by module MVID. See the
/// module documentation for lifetime caveats.
static PROJECTION_STORE: LazyLock<Mutex<HashMap<[u8; 16], ModuleProjections>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn store() -> &'static Mutex<HashMap<[u8; 16], ModuleProjections>> {
    &PROJECTION_STORE
}

fn lock_store() -> std::sync::MutexGuard<'static, HashMap<[u8; 16], ModuleProjections>> {
    // A poisoned store still holds valid records; recover rather than panic.
    store().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Virtual assembly references (AddVirtualReferences / RemoveVirtualReferences)
// ---------------------------------------------------------------------------

/// Version stamped onto every synthesized projection assembly reference.
pub const PROJECTION_VERSION: Version = Version { major: 4, minor: 0, build: 0, revision: 0 };

const CONTRACT_PK_TOKEN: [u8; 8] = [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A];

const CONTRACT_PK: [u8; 160] = [
    0x00, 0x24, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00,
    0x00, 0x24, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x07, 0xD1, 0xFA, 0x57, 0xC4, 0xAE, 0xD9, 0xF0, 0xA3, 0x2E, 0x84, 0xAA, 0x0F, 0xAE, 0xFD, 0x0D,
    0xE9, 0xE8, 0xFD, 0x6A, 0xEC, 0x8F, 0x87, 0xFB, 0x03, 0x76, 0x6C, 0x83, 0x4C, 0x99, 0x92, 0x1E,
    0xB2, 0x3B, 0xE7, 0x9A, 0xD9, 0xD5, 0xDC, 0xC1, 0xDD, 0x9A, 0xD2, 0x36, 0x13, 0x21, 0x02, 0x90,
    0x0B, 0x72, 0x3C, 0xF9, 0x80, 0x95, 0x7F, 0xC4, 0xE1, 0x77, 0x10, 0x8F, 0xC6, 0x07, 0x77, 0x4F,
    0x29, 0xE8, 0x32, 0x0E, 0x92, 0xEA, 0x05, 0xEC, 0xE4, 0xE8, 0x21, 0xC0, 0xA5, 0xEF, 0xE8, 0xF1,
    0x64, 0x5C, 0x4C, 0x0C, 0x93, 0xC1, 0xAB, 0x99, 0x28, 0x5D, 0x62, 0x2C, 0xAA, 0x65, 0x2C, 0x1D,
    0xFA, 0xD6, 0x3D, 0x74, 0x5D, 0x6F, 0x2D, 0xE5, 0xF1, 0x7E, 0x5E, 0xAF, 0x0F, 0xC4, 0x96, 0x3D,
    0x26, 0x1C, 0x8A, 0x12, 0x43, 0x65, 0x18, 0x20, 0x6D, 0xC0, 0x93, 0x34, 0x4D, 0x5A, 0xD2, 0x93,
];

/// Names appended by `add_virtual_references`, in append order.
pub const VIRTUAL_REFERENCE_NAMES: [&str; 6] = [
    "System.Runtime",
    "System.Runtime.InteropServices.WindowsRuntime",
    "System.ObjectModel",
    "System.Runtime.WindowsRuntime",
    "System.Runtime.WindowsRuntime.UI.Xaml",
    "System.Numerics.Vectors",
];

fn build_virtual_references(corlib: &AssemblyNameReference) -> Vec<AssemblyNameReference> {
    let has_pk = corlib.attributes.contains(AssemblyAttributes::PUBLIC_KEY);
    // `public_key_or_token` holds whichever form the row carried; Cecil picks
    // PublicKey vs PublicKeyToken on the same distinction.
    let corlib_key = corlib.public_key_or_token.clone();
    let contract: Vec<u8> = if has_pk { CONTRACT_PK.to_vec() } else { CONTRACT_PK_TOKEN.to_vec() };
    let interop_key = contract.clone();
    let object_model_key = contract.clone();

    let mk = |name: &str, key: &[u8]| {
        let mut r = AssemblyNameReference::new(name);
        r.version = PROJECTION_VERSION;
        r.public_key_or_token = key.to_vec();
        r
    };
    vec![
        mk(VIRTUAL_REFERENCE_NAMES[0], &contract),
        mk(VIRTUAL_REFERENCE_NAMES[1], &interop_key),
        mk(VIRTUAL_REFERENCE_NAMES[2], &object_model_key),
        mk(VIRTUAL_REFERENCE_NAMES[3], &corlib_key),
        mk(VIRTUAL_REFERENCE_NAMES[4], &corlib_key),
        mk(VIRTUAL_REFERENCE_NAMES[5], &contract),
    ]
}

fn add_virtual_references(m: &mut Module) -> Result<(Version, Vec<AssemblyNameReference>)> {
    let ci = m
        .assembly_refs
        .iter()
        .position(|r| r.name == "mscorlib")
        .ok_or_else(|| Error::bad_image("Missing mscorlib reference in AssemblyRef table."))?;
    let saved = m.assembly_refs[ci].version;
    let vrefs = build_virtual_references(&m.assembly_refs[ci]);
    // Force the core library version onto the projection version, like Cecil.
    m.assembly_refs[ci].version = PROJECTION_VERSION;
    m.assembly_refs.extend(vrefs.iter().cloned());
    Ok((saved, vrefs))
}

fn remove_virtual_references(m: &mut Module, st: &ModuleProjections) {
    if let Some(saved) = st.corlib_saved_version {
        if let Some(ci) = m.assembly_refs.iter().position(|r| r.name == "mscorlib") {
            m.assembly_refs[ci].version = saved;
        }
    }
    // Remove the appended rows, matching by name from the back.
    for name in st.virtual_refs_added.iter().rev() {
        if let Some(pos) = m.assembly_refs.iter().rposition(|r| &r.name == name) {
            m.assembly_refs.remove(pos);
        }
    }
}

fn get_virtual_reference(
    vrefs: &[AssemblyNameReference],
    name: &str,
) -> Result<AssemblyNameReference> {
    vrefs
        .iter()
        .find(|r| r.name == name)
        .cloned()
        .ok_or_else(|| Error::invalid_op(format!("missing virtual assembly reference '{name}'")))
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Projects a module in place (reader-side semantics of Cecil's
/// `WindowsRuntimeProjections`). No-op for non-Windows metadata kinds.
///
/// Errors when projections were already applied to this module (detected via
/// its MVID) or when the module lacks an `mscorlib` assembly reference.
pub fn apply_projections(m: &mut Module) -> Result<()> {
    if m.metadata_kind == MetadataKind::Ecma335 {
        return Ok(());
    }
    let guid = m.guid;
    if lock_store().contains_key(&guid) {
        return Err(Error::invalid_op("windows runtime projections already applied"));
    }

    let (saved_version, vrefs) = add_virtual_references(m)?;
    let mut st = ModuleProjections {
        corlib_saved_version: Some(saved_version),
        virtual_refs_added: VIRTUAL_REFERENCE_NAMES.iter().map(|s| s.to_string()).collect(),
        ..ModuleProjections::default()
    };

    project_type_references(m, &vrefs, &mut st.references)?;

    for i in 0..m.types.len() {
        project_type_definition(m, TypeId(i as u32), &mut st)?;
    }
    project_fields(m, &mut st)?;
    for i in 0..m.methods.len() {
        project_method_definition(m, MethodId(i as u32), &mut st)?;
    }
    project_attribute_records(m, &mut st)?;

    lock_store().insert(guid, st);
    Ok(())
}

/// Reverses [`apply_projections`] exactly: names, flags, signatures,
/// attribute blobs and assembly references return to their pre-projection
/// state. No-op when the module was never projected.
pub fn remove_projections(m: &mut Module) -> Result<()> {
    let Some(mut st) = lock_store().remove(&m.guid) else {
        return Ok(());
    };

    remove_attribute_records(m, &mut st);
    for (&fi, rec) in st.fields.iter() {
        if let Some(f) = m.fields.get_mut(fi as usize) {
            f.attributes = rec.attributes;
        }
    }
    for (&mi, rec) in st.methods.iter() {
        if let Some(meth) = m.methods.get_mut(mi as usize) {
            meth.attributes = rec.attributes;
            meth.impl_attributes = rec.impl_attributes;
            meth.name = rec.name.clone();
        }
    }
    for (&ti, rec) in st.types.iter() {
        remove_type_projection(m, TypeId(ti), rec);
    }
    restore_type_references(m, &st.references)?;
    remove_virtual_references(m, &st);
    Ok(())
}

/// Whether the type definition carries an active projection record.
pub fn is_projected_type(m: &Module, id: TypeId) -> bool {
    lock_store().get(&m.guid).map(|st| st.types.contains_key(&id.0)).unwrap_or(false)
}

/// Whether the method definition carries an active projection record.
pub fn is_projected_method(m: &Module, id: MethodId) -> bool {
    lock_store().get(&m.guid).map(|st| st.methods.contains_key(&id.0)).unwrap_or(false)
}

/// Whether the field definition carries an active projection record.
pub fn is_projected_field(m: &Module, id: FieldId) -> bool {
    lock_store().get(&m.guid).map(|st| st.fields.contains_key(&id.0)).unwrap_or(false)
}

/// Whether any projection state is registered for the module.
pub fn has_projections(m: &Module) -> bool {
    lock_store().contains_key(&m.guid)
}

// ---------------------------------------------------------------------------
// Type-reference projection
// ---------------------------------------------------------------------------

/// Port of `GetSpecialTypeReferenceTreatment`.
fn special_type_reference_treatment(ns: &str, name: &str) -> TypeReferenceTreatment {
    if ns == "System" {
        if name == "MulticastDelegate" {
            return TypeReferenceTreatment::SystemDelegate;
        }
        if name == "Attribute" {
            return TypeReferenceTreatment::SystemAttribute;
        }
    }
    TypeReferenceTreatment::None
}

/// Computes how an external (`TypeRef`-equivalent) node projects, mirroring
/// `Project(TypeReference)`.
pub fn type_reference_treatment(e: &ExternalType) -> TypeReferenceTreatment {
    if let Some(info) = well_known_projection(&e.name) {
        if info.winrt_namespace == e.namespace {
            return TypeReferenceTreatment::UseProjectionInfo;
        }
    }
    special_type_reference_treatment(&e.namespace, &e.name)
}

/// Walks every `ExternalType` node reachable from the module and renames it
/// according to the projection table (`ApplyProjection(TypeReference)`).
///
/// Records are indexed by the *post-projection* identity so later passes can
/// map a renamed node back to its original spelling.
fn project_type_references(
    m: &mut Module,
    vrefs: &[AssemblyNameReference],
    refs: &mut HashMap<(String, String), TypeReferenceProjection>,
) -> Result<()> {
    for_each_external(m, &mut |e: &mut ExternalType| {
        // No "already projected" guard: scope-only treatments keep the
        // original identity, so a post-identity key cannot distinguish an
        // unprojected node from a projected one. `apply_projections` runs at
        // most once per module (store-guarded), making this safe.
        let treatment = type_reference_treatment(e);
        if treatment == TypeReferenceTreatment::None {
            return Ok(());
        }
        let record = TypeReferenceProjection {
            name: e.name.clone(),
            namespace: e.namespace.clone(),
            scope: e.scope.clone(),
            treatment,
        };
        match treatment {
            TypeReferenceTreatment::UseProjectionInfo => {
                let info =
                    well_known_projection(&record.name).expect("treatment implies table hit");
                e.name = info.clr_name.to_string();
                e.namespace = info.clr_namespace.to_string();
                e.scope = ScopeRef::Assembly(get_virtual_reference(vrefs, info.clr_assembly)?);
            }
            TypeReferenceTreatment::SystemDelegate | TypeReferenceTreatment::SystemAttribute => {
                e.scope = ScopeRef::Assembly(get_virtual_reference(vrefs, "System.Runtime")?);
            }
            TypeReferenceTreatment::None => unreachable!("filtered above"),
        }
        refs.insert((e.namespace.clone(), e.name.clone()), record);
        Ok(())
    })
}

fn restore_type_references(
    m: &mut Module,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> Result<()> {
    for_each_external(m, &mut |e: &mut ExternalType| {
        if let Some(rec) = refs.get(&(e.namespace.clone(), e.name.clone())) {
            e.name = rec.name.clone();
            e.namespace = rec.namespace.clone();
            e.scope = rec.scope.clone();
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Whole-module traversal helpers
// ---------------------------------------------------------------------------

fn visit_external_chain(
    e: &mut ExternalType,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    f(e)?;
    for n in &mut e.nesting {
        visit_external_chain(n, f)?;
    }
    Ok(())
}

fn walk_type_desc(
    td: &mut TypeDesc,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    match td {
        TypeDesc::External(e) => visit_external_chain(e, f),
        TypeDesc::SzArray(x) | TypeDesc::Ptr(x) | TypeDesc::ByRef(x) | TypeDesc::Pinned(x) => {
            // Copy-on-write: shared subtrees (refcount > 1) are cloned before
            // mutation so projections never bleed across unrelated owners.
            walk_type_desc(std::sync::Arc::make_mut(x), f)
        }
        TypeDesc::Array { element, .. } => walk_type_desc(std::sync::Arc::make_mut(element), f),
        TypeDesc::GenericInstance { definition, arguments } => {
            walk_type_desc(std::sync::Arc::make_mut(definition), f)?;
            for a in arguments {
                walk_type_desc(std::sync::Arc::make_mut(a), f)?;
            }
            Ok(())
        }
        TypeDesc::FnPtr(sig) => {
            for p in &mut sig.parameters {
                walk_type_desc(p, f)?;
            }
            walk_type_desc(&mut sig.return_type, f)
        }
        TypeDesc::CMod { modifier, unmodified, .. } => {
            walk_type_desc(std::sync::Arc::make_mut(modifier), f)?;
            walk_type_desc(std::sync::Arc::make_mut(unmodified), f)
        }
        _ => Ok(()),
    }
}

fn walk_signature(
    sig: &mut MethodSignature,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    for p in &mut sig.parameters {
        walk_type_desc(p, f)?;
    }
    walk_type_desc(&mut sig.return_type, f)
}

fn walk_method_ref(
    mr: &mut MethodRef,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    match mr {
        MethodRef::Def(_) => Ok(()),
        MethodRef::External(em) => {
            walk_type_desc(&mut em.parent, f)?;
            walk_signature(&mut em.signature, f)
        }
        MethodRef::Spec { method, arguments } => {
            walk_method_ref(method, f)?;
            for a in arguments {
                walk_type_desc(a, f)?;
            }
            Ok(())
        }
    }
}

fn walk_field_ref(
    fr: &mut FieldRef,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    match fr {
        FieldRef::Def(_) => Ok(()),
        FieldRef::External(ef) => {
            walk_type_desc(&mut ef.parent, f)?;
            walk_type_desc(&mut ef.signature.0, f)
        }
    }
}

fn walk_marshal(
    mi: &mut Option<MarshalInfo>,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    if let Some(MarshalInfo { spec: NativeTypeSpec::SafeArray { element_desc: Some(d), .. } }) = mi
    {
        walk_type_desc(std::sync::Arc::make_mut(d), f)?;
    }
    Ok(())
}

/// Visits every `ExternalType` node reachable anywhere in the module: base
/// types, interfaces, all member signatures, custom-attribute constructors,
/// overrides, IL operands, constraints and marshal specs.
fn for_each_external(
    m: &mut Module,
    f: &mut dyn FnMut(&mut ExternalType) -> Result<()>,
) -> Result<()> {
    for r in &mut m.assembly_refs {
        for a in &mut r.custom_attributes {
            walk_method_ref(&mut a.constructor, f)?;
        }
    }

    let type_count = m.types.len();
    for i in 0..type_count {
        let members = {
            let t = &m.types[i];
            (t.fields.clone(), t.methods.clone(), t.properties.clone(), t.events.clone())
        };
        {
            let t = &mut m.types[i];
            if let Some(b) = &mut t.base_type {
                walk_type_desc(b, f)?;
            }
            for it in &mut t.interfaces {
                walk_type_desc(it, f)?;
            }
            for a in &mut t.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
        }
        for fid in members.0 {
            let fld = &mut m.fields[fid.index()];
            walk_type_desc(&mut fld.signature.0, f)?;
            for a in &mut fld.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
            walk_marshal(&mut fld.marshal_info, f)?;
        }
        for mid in members.1 {
            let meth = &mut m.methods[mid.index()];
            walk_signature(&mut meth.signature, f)?;
            for o in &mut meth.overrides {
                walk_method_ref(&mut o.body, f)?;
                walk_method_ref(&mut o.declaration, f)?;
            }
            for p in &mut meth.parameters {
                for a in &mut p.custom_attributes {
                    walk_method_ref(&mut a.constructor, f)?;
                }
                walk_marshal(&mut p.marshal_info, f)?;
            }
            for a in &mut meth.return_parameter.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
            walk_marshal(&mut meth.return_parameter.marshal_info, f)?;
            for a in &mut meth.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
            walk_marshal(&mut meth.marshal_info, f)?;
            if let Some(body) = &mut meth.body {
                for ins in &mut body.instructions {
                    match &mut ins.operand {
                        ROperand::Type(t) => walk_type_desc(t, f)?,
                        ROperand::Method(mr) => walk_method_ref(mr, f)?,
                        ROperand::Field(fr) => walk_field_ref(fr, f)?,
                        _ => {}
                    }
                }
            }
        }
        for pid in members.2 {
            let p = &mut m.properties[pid.index()];
            for pt in &mut p.signature.parameters {
                walk_type_desc(pt, f)?;
            }
            walk_type_desc(&mut p.signature.property_type, f)?;
            for a in &mut p.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
        }
        for eid in members.3 {
            let ev = &mut m.events[eid.index()];
            if let Some(et) = &mut ev.event_type {
                walk_type_desc(et, f)?;
            }
            for a in &mut ev.custom_attributes {
                walk_method_ref(&mut a.constructor, f)?;
            }
        }
    }
    for g in &mut m.generic_parameters {
        for c in &mut g.constraints {
            walk_type_desc(c, f)?;
        }
        for a in &mut g.custom_attributes {
            walk_method_ref(&mut a.constructor, f)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared predicates
// ---------------------------------------------------------------------------

fn is_windows_runtime(attrs: TypeAttributes) -> bool {
    attrs.contains(TypeAttributes::WINDOWS_RUNTIME)
}

/// Port of `IsClrImplementationType`: compiler-generated `<CLR>Xxx`
/// implementation types of managed winmds.
pub fn is_clr_implementation_type(t: &crate::model::types::TypeDefinition) -> bool {
    if (t.attributes & (TypeAttributes::VISIBILITY_MASK | TypeAttributes::SPECIAL_NAME))
        != TypeAttributes::SPECIAL_NAME
    {
        return false;
    }
    t.name.starts_with("<CLR>")
}

/// Port of `NeedsWindowsRuntimePrefix`: exactly-public non-interface types
/// whose base type is an external reference other than the System primitives
/// that survive projection.
fn needs_windows_runtime_prefix(t: &crate::model::types::TypeDefinition) -> bool {
    if (t.attributes & (TypeAttributes::VISIBILITY_MASK | TypeAttributes::INTERFACE))
        != TypeAttributes::PUBLIC
    {
        return false;
    }
    let Some(TypeDesc::External(base)) = &t.base_type else { return false };
    if base.namespace == "System"
        && matches!(base.name.as_str(), "Attribute" | "MulticastDelegate" | "ValueType")
    {
        return false;
    }
    true
}

/// `IsAttribute`: base-type reference is the external `System.Attribute`.
fn base_is_attribute(t: &crate::model::types::TypeDefinition) -> bool {
    matches!(&t.base_type, Some(TypeDesc::External(e)) if e.name == "Attribute" && e.namespace == "System")
}

/// `IsEnum`: base-type reference is the external `System.Enum`.
fn base_is_enum(t: &crate::model::types::TypeDefinition) -> bool {
    matches!(&t.base_type, Some(TypeDesc::External(e)) if e.name == "Enum" && e.namespace == "System")
}

/// Port of `GetWellKnownTypeDefinitionTreatment`.
fn well_known_type_definition_treatment(name: &str, namespace: &str) -> TypeDefinitionTreatment {
    let Some(info) = well_known_projection(name) else { return TypeDefinitionTreatment::NONE };
    let treatment = if info.attribute {
        TypeDefinitionTreatment::REDIRECT_TO_CLR_ATTRIBUTE
    } else {
        TypeDefinitionTreatment::REDIRECT_TO_CLR_TYPE
    };
    if namespace == info.clr_namespace {
        return treatment;
    }
    if namespace == info.winrt_namespace {
        return treatment | TypeDefinitionTreatment::INTERNAL;
    }
    TypeDefinitionTreatment::NONE
}

/// Extracts the element `ExternalType` of an attribute constructor's
/// declaring type (stripping generic instantiations).
fn attribute_type_identity(ctor: &MethodRef) -> Option<&ExternalType> {
    match ctor {
        MethodRef::External(em) => element_external(&em.parent),
        _ => None,
    }
}

/// Strips generic-instance/array wrappers down to the underlying external
/// reference (`GetElementType` restricted to TypeRef shapes).
fn element_external(td: &TypeDesc) -> Option<&ExternalType> {
    let mut cur = td;
    loop {
        match cur {
            TypeDesc::External(e) => return Some(e),
            TypeDesc::GenericInstance { definition, .. }
            | TypeDesc::SzArray(definition)
            | TypeDesc::Ptr(definition)
            | TypeDesc::ByRef(definition) => cur = definition,
            TypeDesc::Array { element, .. } => cur = element,
            _ => return None,
        }
    }
}

/// `HasAttribute(customAttributes, ns, name)` — matched by the attribute
/// constructor's declaring-type identity.
fn has_attribute(attrs: &[CustomAttribute], namespace: &str, name: &str) -> bool {
    attrs.iter().any(|a| {
        attribute_type_identity(&a.constructor)
            .is_some_and(|e| e.name == name && e.namespace == namespace)
    })
}

fn is_redirected_type(
    td: &TypeDesc,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> bool {
    element_external(td).is_some_and(|e| {
        refs.get(&(e.namespace.clone(), e.name.clone()))
            .is_some_and(|r| r.treatment == TypeReferenceTreatment::UseProjectionInfo)
    })
}

/// Rebuilds a `TypeDesc` carrying the pre-projection identity of `td`;
/// generic instances keep their (already resolved) arguments.
fn unproject_type(
    td: &TypeDesc,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> Option<TypeDesc> {
    match td {
        TypeDesc::GenericInstance { definition, arguments } => Some(TypeDesc::GenericInstance {
            definition: std::sync::Arc::new(unproject_type(definition, refs)?),
            arguments: arguments.clone(),
        }),
        other => {
            let e = element_external(other)?;
            let rec = refs.get(&(e.namespace.clone(), e.name.clone()))?;
            Some(TypeDesc::External(Box::new(ExternalType {
                namespace: rec.namespace.clone(),
                name: rec.name.clone(),
                nesting: e.nesting.clone(),
                scope: rec.scope.clone(),
            })))
        }
    }
}

/// Resolves a possibly *projected* `TypeDesc` to a locally defined type:
/// tries the node as-is first, then its recorded pre-projection identity
/// (`TypeResolver.Resolve` equivalent for renamed references).
fn resolve_local_maybe_projected(
    m: &Module,
    td: &TypeDesc,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> Option<TypeId> {
    resolve_local(m, td).or_else(|| {
        let un = unproject_type(td, refs)?;
        resolve_local(m, &un)
    })
}

/// Resolves a `TypeDesc` to a locally defined type, walking external nesting
/// chains (`nesting[0]` is the outermost ancestor, `nesting[last]` the
/// immediate parent).
fn resolve_local(m: &Module, td: &TypeDesc) -> Option<TypeId> {
    match td {
        TypeDesc::Def(id) => Some(*id),
        TypeDesc::External(e) => {
            if e.nesting.is_empty() {
                m.get_type_id(&e.namespace, &e.name)
            } else {
                let root = &e.nesting[0];
                let mut cur = m.get_type_id(&root.namespace, &root.name)?;
                for level in &e.nesting[1..] {
                    cur = nested_child(m, cur, &level.name)?;
                }
                nested_child(m, cur, &e.name)
            }
        }
        TypeDesc::GenericInstance { definition, .. } => resolve_local(m, definition),
        _ => None,
    }
}

fn nested_child(m: &Module, parent: TypeId, name: &str) -> Option<TypeId> {
    m.type_def(parent).nested_types.iter().copied().find(|id| m.type_def(*id).name == name)
}

/// Deep-clones a type with generic-variable substitution applied.
fn substitute_type(
    td: &TypeDesc,
    map_v: &dyn Fn(u16) -> Option<TypeDesc>,
    map_m: &mut dyn Fn(u16) -> Option<TypeDesc>,
) -> TypeDesc {
    // Route through the shared signature codec so substitution semantics
    // stay in one implementation.
    let sig = MethodSignature {
        has_this: false,
        explicit_this: false,
        convention: SignatureCallingConvention::Default,
        generic_count: 0,
        parameters: Vec::new(),
        return_type: td.clone(),
        vararg_start: 0,
    };
    substitute_signature(&sig, map_v, map_m).return_type
}

// ---------------------------------------------------------------------------
// Redirect-implemented-methods machinery
// ---------------------------------------------------------------------------

struct GeneratedMethod {
    def: MethodDefinition,
    /// `MethodImpl` declaration this method implements (the interface method).
    declaration: MethodRef,
}

struct RedirectionPlan {
    generated: Vec<GeneratedMethod>,
    pairs: Vec<(TypeDesc, TypeDesc)>,
}

impl RedirectionPlan {
    fn none() -> Self {
        RedirectionPlan { generated: Vec::new(), pairs: Vec::new() }
    }
}

/// Port of `GenerateRedirectionInformation`: detects projected interfaces,
/// plans unprojected duplicates and the redirected method set.
fn generate_redirection_information(
    m: &Module,
    id: TypeId,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> Result<(TypeDefinitionTreatment, RedirectionPlan)> {
    let t = m.type_def(id);
    let implements_projected = t.interfaces.iter().any(|it| is_redirected_type(it, refs));
    if !implements_projected {
        return Ok((TypeDefinitionTreatment::NORMAL_TYPE, RedirectionPlan::none()));
    }

    // Transitive closure of the implemented redirected interfaces.
    let mut all_implemented: Vec<TypeDesc> = Vec::new();
    for it in &t.interfaces {
        if is_redirected_type(it, refs) && !all_implemented.contains(it) {
            // The root itself belongs to the closure, like Cecil's
            // `allImplementedInterfaces.Add(interfaceType)`.
            all_implemented.push(it.clone());
            collect_implemented_interfaces(m, it, refs, &mut all_implemented);
        }
    }

    // Build (projected, unprojected) interface pairs.
    let mut pairs = Vec::new();
    for it in &t.interfaces {
        if is_redirected_type(it, refs) {
            let unprojected = unproject_type(it, refs).ok_or_else(|| {
                Error::invalid_op("redirected interface lost its projection record")
            })?;
            pairs.push((it.clone(), unprojected));
        }
    }

    // Interfaces don't inherit methods of the interfaces they implement.
    let mut generated = Vec::new();
    if !t.attributes.contains(TypeAttributes::INTERFACE) {
        for it in &all_implemented {
            redirect_interface_methods(m, it, refs, &mut generated);
        }
    }

    Ok((
        TypeDefinitionTreatment::REDIRECT_IMPLEMENTED_METHODS,
        RedirectionPlan { generated, pairs },
    ))
}

fn collect_implemented_interfaces(
    m: &Module,
    td: &TypeDesc,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
    results: &mut Vec<TypeDesc>,
) {
    let Some(id) = resolve_local_maybe_projected(m, td, refs) else { return };
    let interfaces = m.type_def(id).interfaces.clone();
    for it in &interfaces {
        // Resolve the interface reference against the declaring generic
        // context (`TypeResolver.Resolve`).
        let resolved = if let TypeDesc::GenericInstance { definition, arguments } = td {
            if resolve_local(m, definition).is_some() {
                let map_v = |n: u16| arguments.get(n as usize).map(|a| a.as_ref().clone());
                let mut no_map = |_n: u16| -> Option<TypeDesc> { None };
                substitute_type(it, &map_v, &mut no_map)
            } else {
                it.clone()
            }
        } else {
            it.clone()
        };
        if !results.contains(&resolved) {
            results.push(resolved.clone());
            collect_implemented_interfaces(m, &resolved, refs, results);
        }
    }
}

/// Port of `RedirectInterfaceMethods`: one Runtime/Final/NewSlot public
/// virtual method per interface method, each overriding the interface
/// method with substituted signature.
fn redirect_interface_methods(
    m: &Module,
    interface_td: &TypeDesc,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
    out: &mut Vec<GeneratedMethod>,
) {
    let Some(id) = resolve_local_maybe_projected(m, interface_td, refs) else { return };
    let map_v = |n: u16| -> Option<TypeDesc> {
        match interface_td {
            TypeDesc::GenericInstance { arguments, .. } => {
                arguments.get(n as usize).map(|a| a.as_ref().clone())
            }
            _ => None,
        }
    };
    let mut no_map = |_n: u16| -> Option<TypeDesc> { None };
    let def = m.type_def(id);
    for mid in &def.methods {
        let src = m.method_def(*mid);
        let sig = substitute_signature(&src.signature, &map_v, &mut no_map);
        let md = MethodDefinition {
            name: src.name.clone(),
            attributes: MethodAttributes::PUBLIC
                | MethodAttributes::VIRTUAL
                | MethodAttributes::FINAL
                | MethodAttributes::NEW_SLOT,
            impl_attributes: MethodImplAttributes::RUNTIME,
            signature: sig.clone(),
            parameters: src.parameters.clone(),
            return_parameter: src.return_parameter.clone(),
            ..Default::default()
        };
        out.push(GeneratedMethod {
            def: md,
            declaration: MethodRef::External(ExternalMethod {
                parent: interface_td.clone(),
                name: src.name.clone(),
                signature: sig,
            }),
        });
    }
}

fn override_declaration_parent(ov: &MethodOverride) -> Option<&TypeDesc> {
    match &ov.declaration {
        MethodRef::External(em) => Some(&em.parent),
        _ => None,
    }
}

fn set_override_declaration_parent(ov: &mut MethodOverride, parent: TypeDesc) {
    if let MethodRef::External(em) = &mut ov.declaration {
        em.parent = parent;
    }
}

// ---------------------------------------------------------------------------
// Type-definition projection
// ---------------------------------------------------------------------------

/// Computes and applies the type-definition projection for one type
/// (`Project(TypeDefinition)` + `ApplyProjection` combined).
fn project_type_definition(m: &mut Module, id: TypeId, st: &mut ModuleProjections) -> Result<()> {
    let kind = m.metadata_kind;
    let (attributes, name, namespace, base_attr, base_special) = {
        let t = m.type_def(id);
        (
            t.attributes,
            t.name.clone(),
            t.namespace.clone(),
            base_is_attribute(t),
            t.attributes.contains(TypeAttributes::INTERFACE),
        )
    };

    let mut treatment = TypeDefinitionTreatment::NONE;
    let mut redirection = RedirectionPlan::none();

    if is_windows_runtime(attributes) {
        if kind == MetadataKind::WindowsMetadata {
            treatment = well_known_type_definition_treatment(&name, &namespace);
            if treatment == TypeDefinitionTreatment::NONE {
                if base_attr {
                    treatment = TypeDefinitionTreatment::NORMAL_ATTRIBUTE;
                } else {
                    let (tr, plan) = generate_redirection_information(m, id, &st.references)?;
                    treatment = tr;
                    redirection = plan;
                }
            }
        } else if kind == MetadataKind::ManagedWindowsMetadata
            && needs_windows_runtime_prefix(m.type_def(id))
        {
            treatment = TypeDefinitionTreatment::PREFIX_WINDOWS_RUNTIME_NAME;
        }

        if (treatment == TypeDefinitionTreatment::PREFIX_WINDOWS_RUNTIME_NAME
            || treatment == TypeDefinitionTreatment::NORMAL_TYPE)
            && !base_special
            && has_attribute(
                &m.type_def(id).custom_attributes,
                "Windows.UI.Xaml",
                "TreatAsAbstractComposableClassAttribute",
            )
        {
            treatment |= TypeDefinitionTreatment::ABSTRACT;
        }
    } else if kind == MetadataKind::ManagedWindowsMetadata
        && is_clr_implementation_type(m.type_def(id))
    {
        treatment = TypeDefinitionTreatment::UNMANGLE_WINDOWS_RUNTIME_NAME;
    }

    if treatment == TypeDefinitionTreatment::NONE {
        return Ok(());
    }

    // Record the original state first; the redirect arm fills in the added
    // method ids while mutating.
    st.types.entry(id.0).or_insert_with(|| TypeDefinitionProjection {
        attributes,
        name: name.clone(),
        treatment,
        redirected_interfaces: redirection.pairs.clone(),
        redirected_method_ids: Vec::new(),
    });

    let existing_methods = m.type_def(id).methods.clone();

    match treatment & TypeDefinitionTreatment::KIND_MASK {
        TypeDefinitionTreatment::NORMAL_TYPE => {
            let t = m.type_mut(id).unwrap();
            t.attributes.insert(TypeAttributes::WINDOWS_RUNTIME | TypeAttributes::IMPORT);
        }
        TypeDefinitionTreatment::NORMAL_ATTRIBUTE => {
            let t = m.type_mut(id).unwrap();
            t.attributes.insert(TypeAttributes::WINDOWS_RUNTIME | TypeAttributes::SEALED);
        }
        TypeDefinitionTreatment::UNMANGLE_WINDOWS_RUNTIME_NAME => {
            let t = m.type_mut(id).unwrap();
            t.attributes.remove(TypeAttributes::SPECIAL_NAME);
            t.attributes.insert(TypeAttributes::PUBLIC);
            t.name = t.name["<CLR>".len()..].to_string();
        }
        TypeDefinitionTreatment::PREFIX_WINDOWS_RUNTIME_NAME => {
            let t = m.type_mut(id).unwrap();
            t.attributes.remove(TypeAttributes::PUBLIC);
            t.attributes.insert(TypeAttributes::IMPORT);
            t.name = format!("<WinRT>{name}");
        }
        TypeDefinitionTreatment::REDIRECT_TO_CLR_TYPE => {
            let t = m.type_mut(id).unwrap();
            t.attributes.remove(TypeAttributes::PUBLIC);
            t.attributes.insert(TypeAttributes::IMPORT);
        }
        TypeDefinitionTreatment::REDIRECT_TO_CLR_ATTRIBUTE => {
            let t = m.type_mut(id).unwrap();
            t.attributes.remove(TypeAttributes::PUBLIC);
        }
        TypeDefinitionTreatment::REDIRECT_IMPLEMENTED_METHODS => {
            {
                let t = m.type_mut(id).unwrap();
                t.attributes.insert(TypeAttributes::WINDOWS_RUNTIME | TypeAttributes::IMPORT);
                for (_projected, unprojected) in &redirection.pairs {
                    // Add the unprojected interface duplicate.
                    t.interfaces.push(unprojected.clone());
                }
            }
            // Rewire overrides pointing at the projected interface to the
            // unprojected duplicate.
            for (projected, unprojected) in &redirection.pairs {
                for mid in &existing_methods {
                    let meth = &mut m.methods[mid.index()];
                    for ov in &mut meth.overrides {
                        if override_declaration_parent(ov) == Some(projected) {
                            set_override_declaration_parent(ov, unprojected.clone());
                        }
                    }
                }
            }
            // Append the redirected methods to the arena + member list.
            let mut added = Vec::new();
            for gm in redirection.generated {
                let mid = MethodId(m.methods.len() as u32);
                let mut def = gm.def;
                def.declaring_type = id;
                def.overrides.push(MethodOverride {
                    body: MethodRef::Def(mid),
                    declaration: gm.declaration,
                });
                m.methods.push(def);
                m.types[id.index()].methods.push(mid);
                added.push(mid);
            }
            let rec = st.types.get_mut(&id.0).unwrap();
            rec.redirected_method_ids = added.to_vec();
            st.added_methods.extend(added.iter().map(|mid| mid.0));
        }
        _ => {}
    }

    if treatment.contains(TypeDefinitionTreatment::ABSTRACT) {
        m.type_mut(id).unwrap().attributes.insert(TypeAttributes::ABSTRACT);
    }
    if treatment.contains(TypeDefinitionTreatment::INTERNAL) {
        m.type_mut(id).unwrap().attributes.remove(TypeAttributes::PUBLIC);
    }

    Ok(())
}

fn remove_type_projection(m: &mut Module, id: TypeId, rec: &TypeDefinitionProjection) {
    {
        let Some(t) = m.type_mut(id) else { return };
        t.attributes = rec.attributes;
        t.name = rec.name.clone();
    }

    if rec.treatment & TypeDefinitionTreatment::KIND_MASK
        != TypeDefinitionTreatment::REDIRECT_IMPLEMENTED_METHODS
    {
        return;
    }

    // Detach the redirected methods from the owning type's member list.
    let added: Vec<MethodId> = rec.redirected_method_ids.clone();
    let kept: Vec<MethodId> = {
        let t = m.type_mut(id).unwrap();
        t.methods.retain(|mid| !added.contains(mid));
        t.methods.clone()
    };

    for (projected, unprojected) in rec.redirected_interfaces.iter().rev() {
        // Rewire overrides back to the projected interface.
        for mid in &kept {
            let meth = &mut m.methods[mid.index()];
            for ov in &mut meth.overrides {
                if override_declaration_parent(ov) == Some(unprojected) {
                    set_override_declaration_parent(ov, projected.clone());
                }
            }
        }
        // Remove the unprojected interface entry (first structural match).
        let t = m.type_mut(id).unwrap();
        if let Some(pos) = t.interfaces.iter().position(|i| i == unprojected) {
            t.interfaces.remove(pos);
        }
    }
}

// ---------------------------------------------------------------------------
// Method-definition projection
// ---------------------------------------------------------------------------

fn method_is_public(attrs: MethodAttributes) -> bool {
    attrs & MethodAttributes::MEMBER_ACCESS_MASK == MethodAttributes::PUBLIC
}

/// `ImplementsRedirectedInterface`: the override's declaring type must be an
/// external type (optionally a generic instance over one) whose identity was
/// renamed by a `UseProjectionInfo` reference projection.
fn implements_redirected_interface(
    parent: Option<&TypeDesc>,
    refs: &HashMap<(String, String), TypeReferenceProjection>,
) -> bool {
    let Some(parent) = parent else { return false };
    let element_ok = match parent {
        TypeDesc::External(_) => true,
        TypeDesc::GenericInstance { definition, .. } => {
            matches!(**definition, TypeDesc::External(_))
        }
        _ => false,
    };
    if !element_ok {
        return false;
    }
    // By the time methods are projected, type projection has already rewired
    // overrides to the *unprojected* interface duplicates, so match against
    // the recorded ORIGINAL identities (Cecil does the same by briefly
    // removing the projection from the declaring type before consulting the
    // table).
    let Some(e) = element_external(parent) else { return false };
    refs.values().any(|r| {
        r.treatment == TypeReferenceTreatment::UseProjectionInfo
            && r.namespace == e.namespace
            && r.name == e.name
    })
}

/// Port of `GetMethodDefinitionTreatmentFromCustomAttributes`.
fn method_treatment_from_attributes(attrs: &[CustomAttribute]) -> MethodDefinitionTreatment {
    let mut treatment = MethodDefinitionTreatment::NONE;
    for a in attrs {
        let Some(e) = attribute_type_identity(&a.constructor) else { continue };
        if e.namespace != "Windows.UI.Xaml" {
            continue;
        }
        if e.name == "TreatAsPublicMethodAttribute" {
            treatment |= MethodDefinitionTreatment::PUBLIC;
            treatment |= MethodDefinitionTreatment::ABSTRACT;
        }
    }
    treatment
}

fn project_method_definition(
    m: &mut Module,
    id: MethodId,
    st: &mut ModuleProjections,
) -> Result<()> {
    if st.added_methods.contains(&id.0) {
        return Ok(()); // synthesized redirected methods are never re-projected
    }
    let kind = m.metadata_kind;
    let (dt_attrs, dt_nested, dt_interface, dt_base, dt_is_clr_impl) = {
        let meth = m.method_def(id);
        let dt = m.type_def(meth.declaring_type);
        (
            dt.attributes,
            dt.declaring_type.is_some(),
            dt.attributes.contains(TypeAttributes::INTERFACE),
            dt.base_type.clone(),
            is_clr_implementation_type(dt),
        )
    };
    let meth_attrs = m.method_def(id).attributes;

    let mut treatment = MethodDefinitionTreatment::NONE;
    let mut other = false;

    if is_windows_runtime(dt_attrs) {
        if dt_is_clr_impl || dt_nested {
            treatment = MethodDefinitionTreatment::NONE;
        } else if dt_interface {
            treatment =
                MethodDefinitionTreatment::RUNTIME | MethodDefinitionTreatment::INTERNAL_CALL;
        } else if kind == MetadataKind::ManagedWindowsMetadata && !method_is_public(meth_attrs) {
            treatment = MethodDefinitionTreatment::NONE;
        } else {
            other = true;
            if let Some(TypeDesc::External(base)) = &dt_base {
                match special_type_reference_treatment(&base.namespace, &base.name) {
                    TypeReferenceTreatment::SystemDelegate => {
                        treatment =
                            MethodDefinitionTreatment::RUNTIME | MethodDefinitionTreatment::PUBLIC;
                        other = false;
                    }
                    TypeReferenceTreatment::SystemAttribute => {
                        treatment = MethodDefinitionTreatment::RUNTIME
                            | MethodDefinitionTreatment::INTERNAL_CALL;
                        other = false;
                    }
                    _ => {}
                }
            }
        }
    }

    if other {
        let mut seen_redirected = false;
        let mut seen_non_redirected = false;
        for ov in &m.method_def(id).overrides {
            let is_external = matches!(ov.declaration, MethodRef::External(_));
            if is_external
                && implements_redirected_interface(override_declaration_parent(ov), &st.references)
            {
                seen_redirected = true;
            } else {
                seen_non_redirected = true;
            }
        }
        if seen_redirected && !seen_non_redirected {
            treatment = MethodDefinitionTreatment::RUNTIME
                | MethodDefinitionTreatment::INTERNAL_CALL
                | MethodDefinitionTreatment::PRIVATE;
            other = false;
        }
    }

    if other {
        treatment |= method_treatment_from_attributes(&m.method_def(id).custom_attributes);
    }

    if treatment == MethodDefinitionTreatment::NONE {
        return Ok(());
    }

    let (attrs, impl_attributes, name) = {
        let meth = m.method_def(id);
        (meth.attributes, meth.impl_attributes, meth.name.clone())
    };
    st.methods.entry(id.0).or_insert(MethodDefinitionProjection {
        attributes: attrs,
        impl_attributes,
        name,
        treatment,
    });
    let meth = m.method_mut(id).unwrap();
    if treatment.contains(MethodDefinitionTreatment::ABSTRACT) {
        meth.attributes.insert(MethodAttributes::ABSTRACT);
    }
    if treatment.contains(MethodDefinitionTreatment::PRIVATE) {
        meth.attributes.remove(MethodAttributes::MEMBER_ACCESS_MASK);
        meth.attributes.insert(MethodAttributes::PRIVATE);
    }
    if treatment.contains(MethodDefinitionTreatment::PUBLIC) {
        meth.attributes.remove(MethodAttributes::MEMBER_ACCESS_MASK);
        meth.attributes.insert(MethodAttributes::PUBLIC);
    }
    if treatment.contains(MethodDefinitionTreatment::RUNTIME) {
        meth.impl_attributes.insert(MethodImplAttributes::RUNTIME);
    }
    if treatment.contains(MethodDefinitionTreatment::INTERNAL_CALL) {
        meth.impl_attributes.insert(MethodImplAttributes::INTERNAL_CALL);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Field-definition projection
// ---------------------------------------------------------------------------

/// Port of `Project(FieldDefinition)`: in Windows metadata, the runtime
/// special-name `value__` backing field of an enum becomes public.
fn project_fields(m: &mut Module, st: &mut ModuleProjections) -> Result<()> {
    if m.metadata_kind != MetadataKind::WindowsMetadata {
        return Ok(());
    }
    for i in 0..m.types.len() {
        let tid = TypeId(i as u32);
        if !base_is_enum(m.type_def(tid)) {
            continue;
        }
        let fids = m.type_def(tid).fields.clone();
        for fid in fids {
            let f = m.field_def(fid);
            if !(f.attributes.contains(FieldAttributes::RTSPECIAL_NAME) && f.name == "value__") {
                continue;
            }
            let original = f.attributes;
            let f = m.field_mut(fid).unwrap();
            f.attributes.remove(FieldAttributes::FIELD_ACCESS_MASK);
            f.attributes.insert(FieldAttributes::PUBLIC);
            st.fields.entry(fid.0).or_insert(FieldDefinitionProjection {
                attributes: original,
                treatment: FieldDefinitionTreatment::PUBLIC,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom-attribute record projection
// ---------------------------------------------------------------------------

/// `IsWindowsAttributeUsageAttribute`: the constructor is a MemberRef whose
/// declaring type is the *already projected* `System.AttributeUsageAttribute`
/// TypeRef. Owners here are always typedefs (we only scan type-level attrs).
fn is_windows_attribute_usage_attribute(attr: &CustomAttribute) -> bool {
    let MethodRef::External(em) = &attr.constructor else { return false };
    let Some(TypeDesc::External(parent)) = element_type_desc(&em.parent) else { return false };
    parent.name == "AttributeUsageAttribute" && parent.namespace == "System"
}

fn element_type_desc(td: &TypeDesc) -> Option<&TypeDesc> {
    let mut cur = td;
    loop {
        match cur {
            TypeDesc::External(_) => return Some(cur),
            TypeDesc::GenericInstance { definition, .. }
            | TypeDesc::SzArray(definition)
            | TypeDesc::Ptr(definition)
            | TypeDesc::ByRef(definition) => cur = definition,
            TypeDesc::Array { element, .. } => cur = element,
            _ => return None,
        }
    }
}

/// Parses the first fixed constructor argument of an `AttributeUsageAttribute`
/// blob: prolog, tag (`0x08` I4 or `0x55` ENUM followed by a compressed TDOR
/// cell), then the i32 payload. Returns `(value, offset_of_value)`.
fn parse_attribute_usage_target(blob: &[u8]) -> Result<(i32, usize)> {
    let mut rd = ByteReader::new(blob);
    if rd.u16()? != 0x0001 {
        return Err(Error::bad_image("invalid custom attribute prolog"));
    }
    match rd.u8()? {
        0x08 => {}
        0x55 => {
            rd.compressed_u32()?;
        }
        tag => {
            return Err(Error::unsupported(format!(
                "unsupported AttributeUsageAttribute argument encoding 0x{tag:02X}"
            )))
        }
    }
    let off = rd.position();
    let value = rd.i32()?;
    Ok((value, off))
}

/// Rewrites the blob: patches the target value in place, bumps `NumNamed`,
/// keeps any pre-existing named bytes, appends an `AllowMultiple` property.
fn patch_attribute_usage_blob(blob: &[u8], targets: i32, allow_multiple: bool) -> Result<Vec<u8>> {
    let (_, off) = parse_attribute_usage_target(blob)?;
    let named_at = off + 4;
    if blob.len() < named_at + 2 {
        return Err(Error::bad_image("truncated custom attribute blob"));
    }
    let numnamed = u16::from_le_bytes([blob[named_at], blob[named_at + 1]]);

    let mut out = blob[..named_at].to_vec();
    out[off..off + 4].copy_from_slice(&targets.to_le_bytes());
    out.extend_from_slice(&(numnamed + 1).to_le_bytes());
    out.extend_from_slice(&blob[named_at + 2..]);

    // Named property: PROPERTY tag (0x54), BOOLEAN type (0x02), SerString
    // name (length 13 < 0x80 -> one length byte), raw bool payload.
    out.push(0x54);
    out.push(0x02);
    out.extend_from_slice(b"\x0dAllowMultiple");
    out.push(u8::from(allow_multiple));
    Ok(out)
}

fn project_attribute_records(m: &mut Module, st: &mut ModuleProjections) -> Result<()> {
    for i in 0..m.types.len() {
        let tid = TypeId(i as u32);
        let (namespace, name, attrs_count) = {
            let t = m.type_def(tid);
            (t.namespace.clone(), t.name.clone(), t.custom_attributes.len())
        };
        for idx in 0..attrs_count {
            let attr = m.type_def(tid).custom_attributes[idx].clone();
            if !is_windows_attribute_usage_attribute(&attr) {
                continue;
            }

            let special = if namespace == "Windows.Foundation.Metadata" {
                match name.as_str() {
                    "VersionAttribute" => Some(CustomAttributeValueTreatment::VersionAttribute),
                    "DeprecatedAttribute" => {
                        Some(CustomAttributeValueTreatment::DeprecatedAttribute)
                    }
                    _ => None,
                }
            } else {
                None
            };
            let treatment = special.unwrap_or_else(|| {
                if has_attribute(
                    &m.type_def(tid).custom_attributes,
                    "Windows.Foundation.Metadata",
                    "AllowMultipleAttribute",
                ) {
                    CustomAttributeValueTreatment::AllowMultiple
                } else {
                    CustomAttributeValueTreatment::AllowSingle
                }
            });

            let (targets, _) = parse_attribute_usage_target(&attr.blob)?;

            let (version_or_deprecated, multiple) = match treatment {
                CustomAttributeValueTreatment::AllowSingle => (false, false),
                CustomAttributeValueTreatment::AllowMultiple => (false, true),
                CustomAttributeValueTreatment::VersionAttribute
                | CustomAttributeValueTreatment::DeprecatedAttribute => (true, true),
                CustomAttributeValueTreatment::None => continue,
            };

            let patched_targets = if version_or_deprecated {
                targets | attribute_targets::CONSTRUCTOR | attribute_targets::PROPERTY
            } else {
                targets
            };

            let patched = patch_attribute_usage_blob(&attr.blob, patched_targets, multiple)?;
            m.type_mut(tid).unwrap().custom_attributes[idx].blob = patched;

            st.attributes.insert(
                (tid.0, idx as u32),
                CustomAttributeValueProjection { targets, treatment, original_blob: attr.blob },
            );
        }
    }
    Ok(())
}

fn remove_attribute_records(m: &mut Module, st: &mut ModuleProjections) {
    for ((ti, idx), rec) in std::mem::take(&mut st.attributes) {
        if let Some(attr) =
            m.types.get_mut(ti as usize).and_then(|t| t.custom_attributes.get_mut(idx as usize))
        {
            attr.blob = rec.original_blob;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        FieldDefinition, FieldSignature, GenericOwner, GenericParameter, TypeDefinition,
    };
    use cecli_core::io::ByteWriter;

    fn fixture_module(kind: MetadataKind, seed: u8) -> Module {
        let mut m = Module { metadata_kind: kind, ..Default::default() };
        m.guid = [seed; 16];
        m.guid[15] = seed.wrapping_add(1); // unique per fixture
        let mut corlib = AssemblyNameReference::new("mscorlib");
        corlib.version = Version::new(255, 255, 255, 255);
        corlib.public_key_or_token = CONTRACT_PK_TOKEN.to_vec();
        m.assembly_refs.push(corlib);
        m
    }

    fn ty(namespace: &str, name: &str, attributes: TypeAttributes) -> TypeDefinition {
        TypeDefinition {
            namespace: namespace.into(),
            name: name.into(),
            attributes,
            ..Default::default()
        }
    }

    fn wr_public() -> TypeAttributes {
        TypeAttributes::PUBLIC | TypeAttributes::WINDOWS_RUNTIME
    }

    fn ext(namespace: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: namespace.into(),
            name: name.into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        }))
    }

    fn gi(def: TypeDesc, args: Vec<TypeDesc>) -> TypeDesc {
        TypeDesc::GenericInstance {
            definition: std::sync::Arc::new(def),
            arguments: args.into_iter().map(std::sync::Arc::new).collect(),
        }
    }

    fn void_sig(ret: TypeDesc) -> MethodSignature {
        MethodSignature { has_this: true, return_type: ret, ..MethodSignature::default() }
    }

    fn add_method(
        m: &mut Module,
        owner: TypeId,
        name: &str,
        attributes: MethodAttributes,
        signature: MethodSignature,
    ) -> MethodId {
        let md =
            MethodDefinition { name: name.into(), attributes, signature, ..Default::default() };
        m.add_method(owner, md)
    }

    /// An `AttributeUsageAttribute` record: ENUM-encoded target argument +
    /// zero named args.
    fn usage_attr(targets: i32) -> CustomAttribute {
        let mut w = ByteWriter::new();
        w.u16(0x0001);
        w.u8(0x55);
        w.compressed_u32(0x2300_0001);
        w.i32(targets);
        w.u16(0);
        CustomAttribute {
            constructor: MethodRef::External(ExternalMethod {
                parent: ext("System", "AttributeUsageAttribute"),
                name: ".ctor".into(),
                signature: MethodSignature {
                    has_this: false,
                    parameters: vec![TypeDesc::Internal("AttributeTargets".into())],
                    ..MethodSignature::default()
                },
            }),
            blob: w.into_vec(),
        }
    }

    fn named_attr(namespace: &str, name: &str) -> CustomAttribute {
        CustomAttribute {
            constructor: MethodRef::External(ExternalMethod {
                parent: ext(namespace, name),
                name: ".ctor".into(),
                signature: MethodSignature::default(),
            }),
            blob: vec![0x01, 0x00],
        }
    }

    /// `AllowMultiple` property entry appended to the blob; final byte is
    /// the boolean payload (Cecil writes `false` for AllowSingle too).
    const fn allow_multiple_tail(value: u8) -> [u8; 17] {
        [
            0x54, 0x02, 13, b'A', b'l', b'l', b'o', b'w', b'M', b'u', b'l', b't', b'i', b'p', b'l',
            b'e', value,
        ]
    }

    /// Snapshot of everything projections touch, for roundtrip comparison.
    fn snapshot(m: &Module) -> Vec<String> {
        let mut out = Vec::new();
        for (ti, t) in m.iter_types() {
            out.push(format!(
                "T {} {:?} {:?} {}",
                m.type_full_name(ti),
                t.attributes.bits(),
                t.base_type,
                t.interfaces.len()
            ));
            for i in &t.interfaces {
                out.push(format!("I {i:?}"));
            }
            for mid in &t.methods {
                let meth = m.method_def(*mid);
                out.push(format!(
                    "M {} {} {} {} {:?}",
                    meth.name,
                    meth.attributes.bits(),
                    meth.impl_attributes.bits(),
                    meth.overrides.len(),
                    meth.overrides,
                ));
            }
            for fid in &t.fields {
                let f = m.field_def(*fid);
                out.push(format!("F {} {}", f.name, f.attributes.bits()));
            }
            for (ai, a) in t.custom_attributes.iter().enumerate() {
                out.push(format!("A {ai} {:02x?}", a.blob));
            }
        }
        for r in &m.assembly_refs {
            out.push(format!("R {} {} {:02x?}", r.name, r.version, r.public_key_or_token));
        }
        out.sort();
        out
    }

    // -- type definitions ----------------------------------------------------

    #[test]
    fn redirect_to_clr_type_roundtrip() {
        // `TypeName` spelled with its ClrNamespace -> plain redirect.
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x11);
        let attrs = wr_public() | TypeAttributes::SEALED;
        let tid = m.add_type(ty("System", "TypeName", attrs));

        apply_projections(&mut m).unwrap();
        assert!(is_projected_type(&m, tid));
        let t = m.type_def(tid);
        assert_eq!(t.name, "TypeName"); // name untouched for redirects
        assert!(t.attributes.contains(TypeAttributes::IMPORT | TypeAttributes::WINDOWS_RUNTIME));
        assert!(!t.attributes.contains(TypeAttributes::PUBLIC));

        remove_projections(&mut m).unwrap();
        assert!(!has_projections(&m));
        assert_eq!(m.type_def(tid).attributes.bits(), attrs.bits());
    }

    #[test]
    fn redirect_to_clr_attribute_and_internal_variant() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x12);
        let tid =
            m.add_type(ty("Windows.Foundation.Metadata", "AttributeUsageAttribute", wr_public()));
        // WinRT namespace spelling -> redirect + Internal (public cleared).
        let plain = m.add_type(ty("Windows.Foundation", "DateTime", wr_public()));

        apply_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert!(!t.attributes.contains(TypeAttributes::PUBLIC));
        assert!(!t.attributes.contains(TypeAttributes::IMPORT)); // attribute form adds none
        assert!(!m.type_def(plain).attributes.contains(TypeAttributes::PUBLIC));

        remove_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).attributes.bits(), wr_public().bits());
        assert_eq!(m.type_def(plain).attributes.bits(), wr_public().bits());
    }

    #[test]
    fn normal_type_with_abstract_flag_winmd() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x13);
        let mut t = ty("Fabrikam", "Widget", wr_public());
        t.base_type = Some(ext("System", "Object"));
        t.custom_attributes
            .push(named_attr("Windows.UI.Xaml", "TreatAsAbstractComposableClassAttribute"));
        let tid = m.add_type(t);

        apply_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert_eq!(t.name, "Widget"); // NormalType keeps the name
        assert!(t.attributes.contains(TypeAttributes::IMPORT));
        assert!(t.attributes.contains(TypeAttributes::ABSTRACT));

        remove_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).attributes.bits(), wr_public().bits());
    }

    #[test]
    fn unmangle_clr_implementation_type() {
        let mut m = fixture_module(MetadataKind::ManagedWindowsMetadata, 0x14);
        let tid = m.add_type(ty("", "<CLR>Helper", TypeAttributes::SPECIAL_NAME));

        apply_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert_eq!(t.name, "Helper");
        assert!(!t.attributes.contains(TypeAttributes::SPECIAL_NAME));
        assert!(t.attributes.contains(TypeAttributes::PUBLIC));

        remove_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert_eq!(t.name, "<CLR>Helper");
        assert_eq!(t.attributes.bits(), TypeAttributes::SPECIAL_NAME.bits());
    }

    #[test]
    fn prefix_winrt_name_managed_winmd() {
        let mut m = fixture_module(MetadataKind::ManagedWindowsMetadata, 0x15);
        let mut t = ty("Fabrikam", "Widget", wr_public());
        t.base_type = Some(ext("System", "Object"));
        let tid = m.add_type(t);

        apply_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert_eq!(t.name, "<WinRT>Widget");
        assert!(!t.attributes.contains(TypeAttributes::PUBLIC));
        assert!(t.attributes.contains(TypeAttributes::IMPORT));

        remove_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert_eq!(t.name, "Widget");
        assert_eq!(t.attributes.bits(), wr_public().bits());
    }

    #[test]
    fn normal_attribute_from_system_attribute_base() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x16);
        let mut t = ty("Fabrikam", "MyAttr", wr_public());
        t.base_type = Some(ext("System", "Attribute"));
        let tid = m.add_type(t);

        apply_projections(&mut m).unwrap();
        let t = m.type_def(tid);
        assert!(t.attributes.contains(TypeAttributes::SEALED | TypeAttributes::WINDOWS_RUNTIME));

        remove_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).attributes.bits(), wr_public().bits());
    }

    #[test]
    fn ecma335_modules_are_left_alone() {
        let mut m = fixture_module(MetadataKind::Ecma335, 0x17);
        let mut t = ty("Windows.Foundation", "DateTime", TypeAttributes::PUBLIC);
        t.base_type = Some(ext("System", "ValueType"));
        m.add_type(t);
        apply_projections(&mut m).unwrap();
        assert_eq!(m.type_def(TypeId(0)).name, "DateTime"); // not renamed
        assert_eq!(m.assembly_refs.len(), 1); // no virtual refs
        assert!(!has_projections(&m));
    }

    // -- type references -------------------------------------------------------

    #[test]
    fn type_reference_renames_and_scope() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x18);
        let mut t = ty("Fabrikam", "Holder", wr_public());
        t.base_type = Some(ext("System", "Object"));
        let tid = m.add_type(t);
        let fid = m.add_field(
            tid,
            FieldDefinition {
                name: "when".into(),
                signature: FieldSignature(ext("Windows.Foundation", "DateTime")),
                ..FieldDefinition::default()
            },
        );

        apply_projections(&mut m).unwrap();
        let f = m.field_def(fid);
        let FieldSignature(TypeDesc::External(e)) = &f.signature else {
            panic!("external expected")
        };
        assert_eq!(e.namespace, "System");
        assert_eq!(e.name, "DateTimeOffset");
        match &e.scope {
            ScopeRef::Assembly(a) => {
                assert_eq!(a.name, "System.Runtime");
                assert_eq!(a.version, PROJECTION_VERSION);
            }
            other => panic!("assembly scope expected, got {other:?}"),
        }

        remove_projections(&mut m).unwrap();
        let f = m.field_def(fid);
        assert_eq!(f.signature.0, ext("Windows.Foundation", "DateTime"));
    }

    #[test]
    fn system_delegate_reference_rescope() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x19);
        let mut del = ty("F", "MyDelegate", wr_public() | TypeAttributes::SEALED);
        del.base_type = Some(ext("System", "MulticastDelegate"));
        m.add_type(del);
        // Standalone delegate-typed field exercises the reference-only path.
        let holder = m.add_type(ty("F", "H", TypeAttributes::PUBLIC));
        let fid = m.add_field(
            holder,
            FieldDefinition {
                name: "d".into(),
                signature: FieldSignature(ext("System", "MulticastDelegate")),
                ..FieldDefinition::default()
            },
        );

        apply_projections(&mut m).unwrap();
        let f = m.field_def(fid);
        let TypeDesc::External(e) = &f.signature.0 else { panic!() };
        assert_eq!(e.name, "MulticastDelegate"); // name kept
        assert!(matches!(&e.scope, ScopeRef::Assembly(a) if a.name == "System.Runtime"));

        remove_projections(&mut m).unwrap();
        let f = m.field_def(fid);
        let TypeDesc::External(e) = &f.signature.0 else { panic!() };
        assert!(matches!(&e.scope, ScopeRef::ThisModule));
    }

    // -- methods ---------------------------------------------------------------

    #[test]
    fn method_delegate_attribute_interface_treatments() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x1a);

        // Delegate-derived: Invoke becomes Runtime|Public.
        let mut del = ty("F", "MyDelegate", wr_public() | TypeAttributes::SEALED);
        del.base_type = Some(ext("System", "MulticastDelegate"));
        let did = m.add_type(del);
        let invoke = add_method(
            &mut m,
            did,
            "Invoke",
            MethodAttributes::PUBLIC | MethodAttributes::HIDE_BY_SIG,
            void_sig(TypeDesc::Sentinel),
        );

        // Attribute-derived: .ctor becomes Runtime|InternalCall.
        let mut attr = ty("F", "MyAttr", wr_public());
        attr.base_type = Some(ext("System", "Attribute"));
        let aid = m.add_type(attr);
        let ctor = add_method(
            &mut m,
            aid,
            ".ctor",
            MethodAttributes::PUBLIC
                | MethodAttributes::HIDE_BY_SIG
                | MethodAttributes::SPECIAL_NAME,
            void_sig(TypeDesc::Sentinel),
        );

        // Interface method: Runtime|InternalCall.
        let iid = m.add_type(ty("F", "IFoo", wr_public() | TypeAttributes::INTERFACE));
        let im = add_method(
            &mut m,
            iid,
            "Do",
            MethodAttributes::PUBLIC
                | MethodAttributes::ABSTRACT
                | MethodAttributes::NEW_SLOT
                | MethodAttributes::HIDE_BY_SIG,
            void_sig(TypeDesc::Sentinel),
        );

        apply_projections(&mut m).unwrap();

        assert!(is_projected_method(&m, invoke));
        let inv = m.method_def(invoke);
        assert!(inv.attributes.contains(MethodAttributes::PUBLIC));
        assert!(inv.impl_attributes.contains(MethodImplAttributes::RUNTIME));

        let ct = m.method_def(ctor);
        assert!(ct.impl_attributes.contains(MethodImplAttributes::RUNTIME));
        assert!(ct.impl_attributes.contains(MethodImplAttributes::INTERNAL_CALL));

        let ifm = m.method_def(im);
        assert!(ifm
            .impl_attributes
            .contains(MethodImplAttributes::RUNTIME | MethodImplAttributes::INTERNAL_CALL));

        remove_projections(&mut m).unwrap();
        assert_eq!(
            m.method_def(invoke).attributes.bits(),
            (MethodAttributes::PUBLIC | MethodAttributes::HIDE_BY_SIG).bits()
        );
        assert!(!m.method_def(invoke).impl_attributes.contains(MethodImplAttributes::RUNTIME));
        assert!(!m
            .method_def(ctor)
            .impl_attributes
            .intersects(MethodImplAttributes::RUNTIME | MethodImplAttributes::INTERNAL_CALL));
        assert!(!m.method_def(im).impl_attributes.contains(MethodImplAttributes::RUNTIME));
    }

    #[test]
    fn method_private_in_managed_winmd_not_projected() {
        let mut m = fixture_module(MetadataKind::ManagedWindowsMetadata, 0x1b);
        let mut t = ty("F", "C", wr_public());
        t.base_type = Some(ext("System", "Object"));
        let cid = m.add_type(t);
        let privm = add_method(
            &mut m,
            cid,
            "Secret",
            MethodAttributes::PRIVATE,
            void_sig(TypeDesc::Sentinel),
        );

        apply_projections(&mut m).unwrap();
        assert!(!is_projected_method(&m, privm));
        assert_eq!(m.method_def(privm).attributes.bits(), MethodAttributes::PRIVATE.bits());
        remove_projections(&mut m).unwrap();
    }

    #[test]
    fn method_xaml_treat_as_attributes() {
        // Windows metadata has no public-visibility gate, so the
        // TreatAsPublicMethodAttribute path is reachable for private methods.
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x1c);
        let mut t = ty("F", "C", wr_public());
        t.base_type = Some(ext("System", "Object"));
        let cid = m.add_type(t);
        let mid =
            add_method(&mut m, cid, "Go", MethodAttributes::PRIVATE, void_sig(TypeDesc::Sentinel));
        m.method_mut(mid)
            .unwrap()
            .custom_attributes
            .push(named_attr("Windows.UI.Xaml", "TreatAsPublicMethodAttribute"));

        apply_projections(&mut m).unwrap();
        let meth = m.method_def(mid);
        assert!(meth.attributes.contains(MethodAttributes::PUBLIC));

        remove_projections(&mut m).unwrap();
        assert_eq!(m.method_def(mid).attributes.bits(), MethodAttributes::PRIVATE.bits());
    }

    // -- fields -----------------------------------------------------------------

    #[test]
    fn enum_value_field_becomes_public() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x1d);
        let mut en = ty("F", "MyEnum", wr_public() | TypeAttributes::SEALED);
        en.base_type = Some(ext("System", "Enum"));
        let eid = m.add_type(en);
        let fid = m.add_field(
            eid,
            FieldDefinition {
                name: "value__".into(),
                attributes: FieldAttributes::RTSPECIAL_NAME | FieldAttributes::PRIVATE,
                signature: FieldSignature(TypeDesc::Internal("int".into())),
                ..FieldDefinition::default()
            },
        );
        let other = m.add_field(
            eid,
            FieldDefinition {
                name: "One".into(),
                attributes: FieldAttributes::STATIC
                    | FieldAttributes::LITERAL
                    | FieldAttributes::PUBLIC,
                signature: FieldSignature(TypeDesc::Internal("F.MyEnum".into())),
                ..FieldDefinition::default()
            },
        );

        apply_projections(&mut m).unwrap();
        assert!(is_projected_field(&m, fid));
        assert!(m.field_def(fid).attributes.contains(FieldAttributes::PUBLIC));
        // Non-special fields untouched.
        assert!(!is_projected_field(&m, other));

        remove_projections(&mut m).unwrap();
        assert_eq!(
            m.field_def(fid).attributes.bits(),
            (FieldAttributes::RTSPECIAL_NAME | FieldAttributes::PRIVATE).bits()
        );
    }

    // -- redirect-implemented-methods --------------------------------------------

    fn build_redirect_fixture(seed: u8) -> (Module, TypeId, TypeId, MethodId, TypeDesc) {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, seed);

        // Local projected interface IIterable`1 with T.First(): T.
        let iid = m.add_type(ty(
            "Windows.Foundation.Collections",
            "IIterable`1",
            wr_public() | TypeAttributes::INTERFACE,
        ));
        m.add_generic_parameter(GenericParameter {
            name: "T".into(),
            position: 0,
            owner: GenericOwner::Type(iid),
            ..Default::default()
        });
        add_method(
            &mut m,
            iid,
            "First",
            MethodAttributes::PUBLIC
                | MethodAttributes::ABSTRACT
                | MethodAttributes::NEW_SLOT
                | MethodAttributes::HIDE_BY_SIG,
            void_sig(TypeDesc::Var(0)),
        );

        // Element type used as the generic argument.
        m.add_type(ty("Fabrikam", "Thing", TypeAttributes::PUBLIC));

        // Class implementing IIterable`1<Thing> with a metadata override.
        let mut cls = ty("Fabrikam", "Widget", wr_public());
        cls.base_type = Some(ext("System", "Object"));
        let iface_ref = gi(
            ext("Windows.Foundation.Collections", "IIterable`1"),
            vec![ext("Fabrikam", "Thing")],
        );
        cls.interfaces.push(iface_ref.clone());
        let wid = m.add_type(cls);
        let impl_id = add_method(
            &mut m,
            wid,
            "First",
            MethodAttributes::PUBLIC
                | MethodAttributes::FINAL
                | MethodAttributes::NEW_SLOT
                | MethodAttributes::VIRTUAL
                | MethodAttributes::HIDE_BY_SIG,
            void_sig(ext("Fabrikam", "Thing")),
        );
        m.method_mut(impl_id).unwrap().overrides.push(MethodOverride {
            body: MethodRef::Def(impl_id),
            declaration: MethodRef::External(ExternalMethod {
                parent: iface_ref.clone(),
                name: "First".into(),
                signature: void_sig(TypeDesc::Var(0)),
            }),
        });
        (m, iid, wid, impl_id, iface_ref)
    }

    #[test]
    fn redirect_implemented_methods_full_cycle() {
        let (mut m, _iid, wid, impl_id, iface_ref) = build_redirect_fixture(0x1e);

        apply_projections(&mut m).unwrap();

        // Reference renamed everywhere; second entry is the fresh duplicate.
        let t = m.type_def(wid);
        assert_eq!(t.interfaces.len(), 2);
        let TypeDesc::GenericInstance { definition, .. } = &t.interfaces[0] else { panic!() };
        let TypeDesc::External(e) = &**definition else { panic!() };
        assert_eq!(e.namespace, "System.Collections.Generic");
        assert_eq!(e.name, "IEnumerable`1");
        assert_eq!(t.interfaces[1], iface_ref);

        // Existing implementation became private runtime icall.
        let impl_meth = m.method_def(impl_id);
        assert!(impl_meth.attributes.contains(MethodAttributes::PRIVATE));
        assert!(impl_meth
            .impl_attributes
            .contains(MethodImplAttributes::RUNTIME | MethodImplAttributes::INTERNAL_CALL));
        // Override rewired to the unprojected interface.
        match &impl_meth.overrides[0].declaration {
            MethodRef::External(em) => assert_eq!(em.parent, iface_ref),
            other => panic!("external declaration expected, got {other:?}"),
        }

        // One redirected method appended.
        let methods = m.type_def(wid).methods.clone();
        assert_eq!(methods.len(), 2);
        let redirected = m.method_def(methods[1]);
        assert_eq!(redirected.name, "First");
        assert_eq!(
            redirected.attributes.bits(),
            (MethodAttributes::PUBLIC
                | MethodAttributes::VIRTUAL
                | MethodAttributes::FINAL
                | MethodAttributes::NEW_SLOT)
                .bits()
        );
        assert_eq!(redirected.impl_attributes.bits(), MethodImplAttributes::RUNTIME.bits());
        // Var(0) substituted with the generic argument.
        assert_eq!(redirected.signature.return_type, ext("Fabrikam", "Thing"));
        let MethodRef::External(decl) = &redirected.overrides[0].declaration else { panic!() };
        // Cecil resolves the overridden method against the *projected*
        // interface reference collected from type.Interfaces.
        let projected_iface = m.type_def(wid).interfaces[0].clone();
        assert_eq!(decl.parent, projected_iface);
        // Substituted signature on the declaration too.
        assert_eq!(decl.signature.return_type, ext("Fabrikam", "Thing"));

        remove_projections(&mut m).unwrap();

        let t = m.type_def(wid);
        assert_eq!(t.interfaces, vec![iface_ref.clone()]);
        assert_eq!(t.methods, vec![impl_id]);
        let impl_meth = m.method_def(impl_id);
        assert!(!impl_meth.attributes.contains(MethodAttributes::PRIVATE));
        assert!(!impl_meth
            .impl_attributes
            .intersects(MethodImplAttributes::RUNTIME | MethodImplAttributes::INTERNAL_CALL));
        match &impl_meth.overrides[0].declaration {
            MethodRef::External(em) => assert_eq!(em.parent, iface_ref),
            other => panic!("{other:?}"),
        }
    }

    // -- custom attribute records --------------------------------------------------

    #[test]
    fn attribute_record_allow_single_patched_and_restored() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x1f);
        let mut t = ty("F", "MyAttr", wr_public());
        t.base_type = Some(ext("System", "Attribute"));
        t.custom_attributes.push(usage_attr(attribute_targets::CLASS));
        let tid = m.add_type(t);

        let before = m.type_def(tid).custom_attributes[0].blob.clone();

        apply_projections(&mut m).unwrap();
        let blob = &m.type_def(tid).custom_attributes[0].blob;
        // Target value untouched, NumNamed bumped, AllowMultiple=true appended.
        let (targets, _) = parse_attribute_usage_target(blob).unwrap();
        assert_eq!(targets, attribute_targets::CLASS);
        let head = before.len() - 2; // everything before NumNamed
        assert_eq!(&blob[..head], &before[..head]);
        assert_eq!(&blob[head..head + 2], &[0x01, 0x00]); // NumNamed = 1
        assert_eq!(
            &blob[blob.len() - 17..],
            &allow_multiple_tail(0x00),
            "AllowSingle still appends AllowMultiple=false"
        );

        remove_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).custom_attributes[0].blob, before);
    }

    #[test]
    fn attribute_record_version_deprecated_allowmultiple() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x20);

        // VersionAttribute: targets gain Constructor|Property, AllowMultiple=false.
        let mut ver = ty("Windows.Foundation.Metadata", "VersionAttribute", wr_public());
        ver.custom_attributes
            .push(usage_attr(attribute_targets::CLASS | attribute_targets::METHOD));
        let vid = m.add_type(ver);

        // Plain owner carrying AllowMultipleAttribute -> AllowMultiple=true.
        let mut pl = ty("F", "Multi", wr_public());
        pl.custom_attributes
            .push(named_attr("Windows.Foundation.Metadata", "AllowMultipleAttribute"));
        pl.custom_attributes.push(usage_attr(attribute_targets::CLASS));
        let pid = m.add_type(pl);

        apply_projections(&mut m).unwrap();

        let vblob = &m.type_def(vid).custom_attributes[0].blob;
        let (targets, _) = parse_attribute_usage_target(vblob).unwrap();
        assert_eq!(
            targets,
            attribute_targets::CLASS
                | attribute_targets::METHOD
                | attribute_targets::CONSTRUCTOR
                | attribute_targets::PROPERTY
        );
        // Cecil sets AllowMultiple=true for Version/DeprecatedAttribute.
        assert_eq!(*vblob.last().unwrap(), 0x01);

        let pblob = &m.type_def(pid).custom_attributes[1].blob;
        assert_eq!(*pblob.last().unwrap(), 0x01);

        remove_projections(&mut m).unwrap();
        assert_eq!(
            m.type_def(vid).custom_attributes[0].blob,
            usage_attr(attribute_targets::CLASS | attribute_targets::METHOD).blob
        );
        assert_eq!(
            m.type_def(pid).custom_attributes[1].blob,
            usage_attr(attribute_targets::CLASS).blob
        );
    }

    #[test]
    fn non_usage_attributes_untouched() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x21);
        let mut t = ty("F", "T", wr_public());
        t.custom_attributes
            .push(named_attr("Windows.Foundation.Metadata", "AllowMultipleAttribute"));
        let tid = m.add_type(t);
        let before = m.type_def(tid).custom_attributes[0].blob.clone();
        apply_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).custom_attributes[0].blob, before);
        remove_projections(&mut m).unwrap();
        assert_eq!(m.type_def(tid).custom_attributes[0].blob, before);
    }

    // -- virtual assembly references -------------------------------------------------

    #[test]
    fn virtual_references_added_and_removed() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x22);
        let mut t = ty("Fabrikam", "W", wr_public());
        t.base_type = Some(ext("System", "Object"));
        m.add_type(t);

        apply_projections(&mut m).unwrap();
        assert_eq!(m.assembly_refs.len(), 7);
        assert_eq!(m.assembly_refs[0].name, "mscorlib");
        assert_eq!(m.assembly_refs[0].version, PROJECTION_VERSION); // forced 4.0.0.0
        let sr = m.assembly_refs.iter().find(|r| r.name == "System.Runtime").unwrap();
        assert_eq!(sr.version, PROJECTION_VERSION);
        assert_eq!(sr.public_key_or_token, CONTRACT_PK_TOKEN);
        let wr =
            m.assembly_refs.iter().find(|r| r.name == "System.Runtime.WindowsRuntime").unwrap();
        assert_eq!(wr.public_key_or_token, CONTRACT_PK_TOKEN); // inherited from corlib

        remove_projections(&mut m).unwrap();
        assert_eq!(m.assembly_refs.len(), 1);
        assert_eq!(m.assembly_refs[0].version, Version::new(255, 255, 255, 255));
    }

    // -- lifecycle ---------------------------------------------------------------------

    #[test]
    fn double_apply_errors_and_remove_without_apply_is_noop() {
        let mut m = fixture_module(MetadataKind::WindowsMetadata, 0x23);
        let mut t = ty("Fabrikam", "W", wr_public());
        t.base_type = Some(ext("System", "Object"));
        m.add_type(t);

        apply_projections(&mut m).unwrap();
        assert!(matches!(apply_projections(&mut m), Err(Error::InvalidOperation(_))));

        // A different, never-applied module: remove is a no-op.
        let mut fresh = fixture_module(MetadataKind::WindowsMetadata, 0x24);
        fresh.add_type(ty("F", "X", TypeAttributes::PUBLIC));
        remove_projections(&mut fresh).unwrap();
        assert_eq!(fresh.assembly_refs.len(), 1);
        assert!(!has_projections(&fresh));
    }

    /// Kitchen-sink module exercising several treatments at once; verifies
    /// apply -> remove restores the exact snapshot.
    #[test]
    fn roundtrip_snapshot_equality_composite() {
        let (mut m, _iid, _wid, _impl_id, _iface) = build_redirect_fixture(0x25);

        // Well-known redirect + attribute record.
        let mut tn = ty("System", "TypeName", wr_public());
        tn.custom_attributes.push(usage_attr(attribute_targets::STRUCT));
        m.add_type(tn);

        let before = snapshot(&m);
        apply_projections(&mut m).unwrap();
        let during = snapshot(&m);
        assert_ne!(before, during, "projection must change something");
        remove_projections(&mut m).unwrap();
        assert_eq!(before, snapshot(&m), "roundtrip must restore the exact snapshot");
    }

    // -- name-table lookups --------------------------------------------------------------

    #[test]
    fn projection_table_lookup() {
        assert_eq!(PROJECTIONS.len(), 50);
        assert!(well_known_projection("DateTime").is_some());
        assert!(well_known_projection("IIterable`1").is_some());
        assert!(well_known_projection("AttributeUsageAttribute").unwrap().attribute);
        assert!(!well_known_projection("DateTime").unwrap().attribute);
        assert!(well_known_projection("NotATableEntry").is_none());

        // Right name, wrong namespace -> no projection.
        let e = ExternalType {
            namespace: "Wrong".into(),
            name: "DateTime".into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        };
        assert_eq!(type_reference_treatment(&e), TypeReferenceTreatment::None);
        let e = ExternalType {
            namespace: "Windows.Foundation".into(),
            name: "DateTime".into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        };
        assert_eq!(type_reference_treatment(&e), TypeReferenceTreatment::UseProjectionInfo);

        // Special System types.
        let e = ExternalType {
            namespace: "System".into(),
            name: "MulticastDelegate".into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        };
        assert_eq!(type_reference_treatment(&e), TypeReferenceTreatment::SystemDelegate);
        let e = ExternalType {
            namespace: "System".into(),
            name: "Attribute".into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        };
        assert_eq!(type_reference_treatment(&e), TypeReferenceTreatment::SystemAttribute);
    }
}
