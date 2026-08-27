//! Port of Mono.Cecil `TypeParser.cs`: parse fully-qualified CLR type names into
//! [`TypeDesc::External`] trees.
//!
//! Supported grammar (mirrors `Mono.Cecil.TypeParser`):
//! `namespace.Name` / `namespace.Name+Nested+...`, generic arity suffix `` `N `` with an
//! argument list `[arg,arg,...]` (each argument optionally assembly-qualified and wrapped
//! in brackets: `[[Ns.T, Assembly, Version=1.0.0.0]]`), pointer `*`, by-ref `&`,
//! sz-array `[]`, and multi-dimensional arrays with optional bounds `[0...,0:5]`.
//! `\` escapes a delimiter character inside name parts.
//!
//! Deliberate divergences from the C# original:
//! - The parser is strict: trailing garbage, unterminated brackets, and generic arity
//!   mismatches (declared `` `N `` vs actual argument count) yield `Err`.
//! - A bracketed argument list `[[a],[b]]` without a declared `` `N `` suffix is still
//!   accepted (inferred arity), so names like `Ns.Outer+Inner[[Ns.A]]` parse.
//! - Whitespace inside a name part is rejected (it can only be trailing garbage);
//!   whitespace around commas and brackets is trimmed, as in the C# parser.
//! - `modreq(...)`/`modopt(...)` custom modifiers in a type name are rejected with
//!   [`Error::Unsupported`] (they are not representable in this grammar port).
//! - Multi-dimensional bounds (`[lower...,lower:size]`) are parsed into
//!   [`TypeDesc::Array`] sizes/lobounds; the C# parser only records the rank.

use crate::model::types::*;
use cecli_core::{Error, Result};

/// Spec entry parsed after the type name (`*`, `&`, `[]`, `[rank]`).
#[derive(Debug, Clone, PartialEq)]
enum Spec {
    Ptr,
    ByRef,
    SzArray,
    Array { rank: usize, sizes: Vec<i32>, lobounds: Vec<i32> },
}

/// Intermediate parse-tree node mirroring `TypeParser.Type`.
struct ParsedType {
    fullname: String,
    nested_names: Vec<String>,
    arity: usize,
    specs: Vec<Spec>,
    generic_arguments: Option<Vec<ParsedType>>,
    assembly: String,
}

fn is_delimiter(c: char) -> bool {
    matches!(c, '+' | ',' | '[' | ']' | '*' | '&')
}

/// LastIndexOf('`') + int.TryParse suffix, per `TypeParser.TryGetArity(string, out int)`.
fn try_get_arity(name: &str) -> Option<usize> {
    let index = name.rfind('`')?;
    let suffix = &name[index + 1..];
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<usize>().ok()
}

struct Parser {
    chars: Vec<char>,
    position: usize,
}

impl Parser {
    fn new(fullname: &str) -> Self {
        Parser { chars: fullname.chars().collect(), position: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn try_parse(&mut self, chr: char) -> bool {
        if self.peek() == Some(chr) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn try_parse_white_space(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.position += 1;
        }
    }

    /// `ParsePart`: consume until a delimiter, honoring `\` escapes.
    fn parse_part(&mut self) -> String {
        let mut part = String::new();
        while let Some(chr) = self.peek() {
            if is_delimiter(chr) {
                break;
            }
            self.position += 1;
            if chr == '\\' {
                match self.peek() {
                    Some(escaped) => {
                        self.position += 1;
                        part.push(escaped);
                    }
                    None => part.push('\\'),
                }
            } else {
                part.push(chr);
            }
        }
        part
    }

    fn parse_nested_names(&mut self) -> Vec<String> {
        let mut nested = Vec::new();
        while self.try_parse('+') {
            nested.push(self.parse_part().trim().to_string());
        }
        nested
    }

    fn parse_type(&mut self, fq_name: bool) -> Result<ParsedType> {
        self.try_parse_white_space();
        let fullname = self.parse_part();
        if fullname.trim().is_empty() {
            return Err(Error::argument("expected a type name"));
        }
        // Delimiters never include whitespace, so any interior whitespace means the
        // input carries trailing garbage (`System.Int32 x`).
        let fullname = match fullname.split_whitespace().collect::<Vec<_>>()[..] {
            [single] => single.to_string(),
            _ => {
                return Err(Error::argument(format!(
                    "unexpected whitespace in type name `{fullname}'"
                )))
            }
        };

        let nested_names = self.parse_nested_names();

        // TryGetArity sums the `N suffixes of the full name and every nested name.
        let mut arity = try_get_arity(&fullname).unwrap_or(0);
        for nested in &nested_names {
            arity += try_get_arity(nested).unwrap_or(0);
        }
        let generic_arguments = if arity > 0 {
            Some(self.parse_generic_arguments(Some(arity))?)
        } else if self.peek() == Some('[') && self.chars.get(self.position + 1) == Some(&'[') {
            // Inferred arity: record the actual argument count so downstream
            // validation sees a consistent node.
            let arguments = self.parse_generic_arguments(None)?;
            arity = arguments.len();
            Some(arguments)
        } else {
            None
        };

        let specs = self.parse_specs()?;

        let assembly = if fq_name { self.parse_assembly_name() } else { String::new() };

        Ok(ParsedType { fullname, nested_names, arity, specs, generic_arguments, assembly })
    }

    /// `ParseSpecs`. Strict about closing brackets; multi-dimensional lists may carry
    /// dimension bounds (`[0...,0:5]`, `[,]`, `[*]`).
    fn parse_specs(&mut self) -> Result<Vec<Spec>> {
        let mut specs = Vec::new();
        while let Some(chr) = self.peek() {
            match chr {
                '*' => {
                    self.position += 1;
                    specs.push(Spec::Ptr);
                }
                '&' => {
                    self.position += 1;
                    specs.push(Spec::ByRef);
                }
                '[' => {
                    self.position += 1;
                    match self.peek() {
                        Some(']') => {
                            self.position += 1;
                            specs.push(Spec::SzArray);
                        }
                        Some('*') => {
                            self.position += 1;
                            if !self.try_parse(']') {
                                return Err(Error::argument(
                                    "unterminated `[*]' array specification",
                                ));
                            }
                            specs.push(Spec::Array {
                                rank: 1,
                                sizes: Vec::new(),
                                lobounds: Vec::new(),
                            });
                        }
                        _ => specs.push(self.parse_dimensions()?),
                    }
                }
                _ => break,
            }
        }
        Ok(specs)
    }

    /// One multi-dimensional array bracket: comma-separated dimension tokens followed
    /// by `]`. Each token may be empty, `lower...`, `lower:size`, or a bare size.
    fn parse_dimensions(&mut self) -> Result<Spec> {
        let mut rank = 0usize;
        let mut sizes = Vec::new();
        let mut lobounds = Vec::new();
        loop {
            let mut token = String::new();
            while let Some(chr) = self.peek() {
                if chr == ',' || chr == ']' {
                    break;
                }
                self.position += 1;
                token.push(chr);
            }
            let token = token.trim();
            if !token.is_empty() {
                let (lo, size) = parse_dimension(token)?;
                if let Some(lo) = lo {
                    lobounds.push(lo);
                }
                if let Some(size) = size {
                    sizes.push(size);
                }
            }
            rank += 1;
            if !self.try_parse(',') {
                break;
            }
        }
        if !self.try_parse(']') {
            return Err(Error::argument("unterminated array dimension list"));
        }
        Ok(Spec::Array { rank, sizes, lobounds })
    }

    /// `ParseGenericArguments`: reads the argument list inside one outer bracket pair.
    /// With `Some(arity)` (declared `` `N `` suffix) exactly that many arguments are
    /// required; with `None` the count is inferred from the list itself. Each
    /// argument may be wrapped in its own brackets when assembly-qualified.
    /// Whitespace around commas is tolerated.
    fn parse_generic_arguments(&mut self, arity: Option<usize>) -> Result<Vec<ParsedType>> {
        self.try_parse_white_space();
        if self.peek() != Some('[') {
            return Err(Error::argument(format!(
                "generic arity {} declared but no generic argument list follows",
                arity.unwrap_or(0)
            )));
        }
        self.position += 1;

        let mut arguments = Vec::new();
        loop {
            self.try_parse_white_space();
            let fq_argument = self.try_parse('[');
            arguments.push(self.parse_type(fq_argument)?);
            if fq_argument && !self.try_parse(']') {
                return Err(Error::argument("unterminated generic argument"));
            }

            match arity {
                Some(expected) => {
                    if arguments.len() == expected {
                        break;
                    }
                    self.try_parse_white_space();
                    if !self.try_parse(',') {
                        return Err(Error::argument(format!(
                            "generic arity {expected} but only {} argument(s) present",
                            arguments.len()
                        )));
                    }
                }
                None => {
                    // Inferred count: stop at the first missing separator.
                    self.try_parse_white_space();
                    if !self.try_parse(',') {
                        break;
                    }
                }
            }
        }

        self.try_parse_white_space();
        if !self.try_parse(']') {
            return Err(match arity {
                Some(_) => Error::argument("more generic arguments than declared arity"),
                None => Error::argument("unterminated generic argument list"),
            });
        }
        Ok(arguments)
    }

    /// `ParseAssemblyName`: everything up to the next bracket, trimmed. Empty when no
    /// qualifier is present.
    fn parse_assembly_name(&mut self) -> String {
        if !self.try_parse(',') {
            return String::new();
        }
        self.try_parse_white_space();
        let start = self.position;
        while let Some(chr) = self.peek() {
            if chr == '[' || chr == ']' {
                break;
            }
            self.position += 1;
        }
        let text: String = self.chars[start..self.position].iter().collect();
        text.trim().to_string()
    }
}

/// Parse a single dimension token into `(lower bound, size)`; `None` entries mean the
/// bound is unspecified. `0...` -> lower bound 0, `0:5` -> lower 0 size 5, bare number
/// -> size, empty -> unspecified.
fn parse_dimension(token: &str) -> Result<(Option<i32>, Option<i32>)> {
    fn num(text: &str) -> Result<i32> {
        text.parse::<i32>().map_err(|_| Error::argument(format!("invalid array bound `{text}'")))
    }
    if let Some((lo, size)) = token.split_once(':') {
        let lo = lo.trim();
        let size = size.trim();
        Ok((
            (!lo.is_empty()).then(|| num(lo)).transpose()?,
            (!size.is_empty()).then(|| num(size)).transpose()?,
        ))
    } else if let Some(prefix) = token.strip_suffix("...") {
        Ok((Some(num(prefix.trim())?), None))
    } else {
        Ok((None, Some(num(token)?)))
    }
}

/// `SplitFullName`: namespace is everything before the last dot.
fn split_full_name(fullname: &str) -> (&str, &str) {
    match fullname.rfind('.') {
        None => ("", fullname),
        Some(last_dot) => (&fullname[..last_dot], &fullname[last_dot + 1..]),
    }
}

/// Resolve a parsed assembly qualifier against the known scopes by simple name
/// (case-insensitive); unmatched qualifiers fall back to [`ScopeRef::Moduleless`],
/// mirroring `ModuleDefinition.TryGetAssemblyNameReference` + the Cecil fallback that
/// keeps the unparsed reference.
fn resolve_scope(assembly: &str, scopes: &[AssemblyNameReference]) -> ScopeRef {
    let simple = assembly.split(',').next().unwrap_or("").trim();
    for reference in scopes {
        if reference.name.eq_ignore_ascii_case(simple) {
            return ScopeRef::Assembly(reference.clone());
        }
    }
    ScopeRef::Moduleless
}

/// Build the [`TypeDesc`] from a parsed node: external chain first (outermost root,
/// innermost returned), then generic instantiation over it, then the spec wrappers
/// applied outside-in (first spec outermost), like `CreateSpecs`.
fn build_type_desc(
    info: ParsedType,
    base_scope: ScopeRef,
    scopes: &[AssemblyNameReference],
) -> TypeDesc {
    let scope = if info.assembly.is_empty() {
        base_scope.clone()
    } else {
        resolve_scope(&info.assembly, scopes)
    };

    let (nspace, name) = split_full_name(&info.fullname);
    let mut current = ExternalType {
        namespace: nspace.to_string(),
        name: name.to_string(),
        nesting: Vec::new(),
        scope: scope.clone(),
    };
    for nested in &info.nested_names {
        current = ExternalType {
            namespace: String::new(),
            name: nested.clone(),
            nesting: vec![Box::new(current)],
            scope: scope.clone(),
        };
    }

    let mut ty = TypeDesc::External(Box::new(current));

    if let Some(arguments) = info.generic_arguments {
        debug_assert_eq!(arguments.len(), info.arity);
        let arguments = arguments
            .into_iter()
            .map(|arg| std::sync::Arc::new(build_type_desc(arg, base_scope.clone(), scopes)))
            .collect();
        ty = TypeDesc::GenericInstance { definition: std::sync::Arc::new(ty), arguments };
    }

    for spec in info.specs {
        ty = match spec {
            Spec::Ptr => TypeDesc::Ptr(std::sync::Arc::new(ty)),
            Spec::ByRef => TypeDesc::ByRef(std::sync::Arc::new(ty)),
            Spec::SzArray => TypeDesc::SzArray(std::sync::Arc::new(ty)),
            Spec::Array { rank: _, sizes, lobounds } => {
                TypeDesc::Array { element: std::sync::Arc::new(ty), sizes, lobounds }
            }
        };
    }
    ty
}

fn parse_impl(
    full_name: &str,
    base_scope: ScopeRef,
    scopes: &[AssemblyNameReference],
) -> Result<TypeDesc> {
    let full_name = full_name.trim();
    if full_name.is_empty() {
        return Err(Error::argument("type name is empty"));
    }
    if full_name.contains("modreq(") || full_name.contains("modopt(") {
        return Err(Error::unsupported(
            "custom modifiers (modreq/modopt) are not supported by the type-name parser",
        ));
    }

    let mut parser = Parser::new(full_name);
    let info = parser.parse_type(true)?;
    if parser.position != parser.chars.len() {
        return Err(Error::argument(format!(
            "trailing characters at offset {} in `{full_name}'",
            parser.position
        )));
    }
    Ok(build_type_desc(info, base_scope, scopes))
}

/// Parse a fully-qualified CLR type name. Types carrying no assembly qualifier get
/// `default_scope`; qualified types cannot be resolved without a scope list and fall
/// back to [`ScopeRef::Moduleless`] — prefer [`parse_type_name_scoped`] when
/// assembly-qualified names are expected.
pub fn parse_type_name(full_name: &str, default_scope: ScopeRef) -> Result<TypeDesc> {
    parse_impl(full_name, default_scope, &[])
}

/// Like [`parse_type_name`], resolving `, AssemblyName` qualifiers against
/// `assembly_scopes` by simple (case-insensitive) name; unknown assemblies yield
/// [`ScopeRef::Moduleless`].
pub fn parse_type_name_scoped(
    full_name: &str,
    module_scope: ScopeRef,
    assembly_scopes: &[AssemblyNameReference],
) -> Result<TypeDesc> {
    parse_impl(full_name, module_scope, assembly_scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moduleless_scopes() -> Vec<AssemblyNameReference> {
        let mut lib = AssemblyNameReference::new("MyLib");
        lib.version = Version::new(1, 0, 0, 0);
        vec![lib]
    }

    fn external(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        }))
    }

    #[test]
    fn plain_namespace_type() {
        let ty = parse_type_name("System.String", ScopeRef::ThisModule).unwrap();
        assert_eq!(ty, external("System", "String"));
    }

    #[test]
    fn generic_instance_two_args() {
        let ty = parse_type_name(
            "System.Collections.Generic.Dictionary`2[[System.String],[System.Int32]]",
            ScopeRef::ThisModule,
        )
        .unwrap();
        match ty {
            TypeDesc::GenericInstance { definition, arguments } => {
                assert_eq!(*definition, external("System.Collections.Generic", "Dictionary`2"));
                assert_eq!(arguments.len(), 2);
                assert_eq!(*arguments[0], external("System", "String"));
                assert_eq!(*arguments[1], external("System", "Int32"));
            }
            other => panic!("expected GenericInstance, got {other:?}"),
        }
    }

    #[test]
    fn nested_chain_with_generic_argument() {
        let ty = parse_type_name("Ns.Outer+Inner[[Ns.A]]", ScopeRef::ThisModule).unwrap();
        let TypeDesc::GenericInstance { definition, arguments } = ty else {
            panic!("expected GenericInstance");
        };
        assert_eq!(arguments, vec![std::sync::Arc::new(external("Ns", "A"))]);
        let TypeDesc::External(inner) = definition.as_ref() else { panic!("expected External") };
        assert_eq!(inner.namespace, "");
        assert_eq!(inner.name, "Inner");
        assert_eq!(inner.nesting.len(), 1);
        let outer = &inner.nesting[0];
        assert_eq!((outer.namespace.as_str(), outer.name.as_str()), ("Ns", "Outer"));
    }

    #[test]
    fn pointer_byref_and_arrays() {
        assert_eq!(
            parse_type_name("System.Int32*", ScopeRef::ThisModule).unwrap(),
            TypeDesc::Ptr(std::sync::Arc::new(external("System", "Int32")))
        );
        assert_eq!(
            parse_type_name("System.Int32&", ScopeRef::ThisModule).unwrap(),
            TypeDesc::ByRef(std::sync::Arc::new(external("System", "Int32")))
        );

        let md = parse_type_name("System.Int32[0...,0:5]", ScopeRef::ThisModule).unwrap();
        match md {
            TypeDesc::Array { element, sizes, lobounds } => {
                assert_eq!(*element, external("System", "Int32"));
                assert_eq!(sizes, vec![5]);
                assert_eq!(lobounds, vec![0, 0]);
            }
            other => panic!("expected Array, got {other:?}"),
        }

        // Jagged: [][] composes as SzArray(SzArray).
        let jagged = parse_type_name("System.Int32[][]", ScopeRef::ThisModule).unwrap();
        match jagged {
            TypeDesc::SzArray(inner) => match inner.as_ref() {
                TypeDesc::SzArray(innermost) => {
                    assert_eq!(**innermost, external("System", "Int32"))
                }
                other => panic!("expected SzArray element, got {other:?}"),
            },
            other => panic!("expected SzArray, got {other:?}"),
        }
    }

    #[test]
    fn assembly_qualified_resolves_against_scopes() {
        let scopes = moduleless_scopes();
        let ty =
            parse_type_name_scoped("My.T, MyLib, Version=1.0.0.0", ScopeRef::ThisModule, &scopes)
                .unwrap();
        match ty {
            TypeDesc::External(ext) => {
                assert_eq!((ext.namespace.as_str(), ext.name.as_str()), ("My", "T"));
                match ext.scope {
                    ScopeRef::Assembly(anr) => {
                        assert_eq!(anr.name, "MyLib");
                        assert_eq!(anr.version, Version::new(1, 0, 0, 0));
                    }
                    other => panic!("expected Assembly scope, got {other:?}"),
                }
            }
            other => panic!("expected External, got {other:?}"),
        }

        // Unknown assembly simple name falls back to Moduleless.
        let ty = parse_type_name_scoped("Other.T, NoLib", ScopeRef::ThisModule, &scopes).unwrap();
        let TypeDesc::External(ext) = ty else { panic!("expected External") };
        assert_eq!(ext.scope, ScopeRef::Moduleless);

        // Unqualified names keep the module scope even when scopes are supplied.
        let ty = parse_type_name_scoped("Local.T", ScopeRef::ThisModule, &scopes).unwrap();
        let TypeDesc::External(ext) = ty else { panic!("expected External") };
        assert_eq!(ext.scope, ScopeRef::ThisModule);
    }

    #[test]
    fn errors_on_mismatch_garbage_and_empty() {
        // Arity mismatch: fewer args than declared.
        assert!(parse_type_name("Ns.Dict`2[[Ns.A]]", ScopeRef::ThisModule).is_err());
        // Arity mismatch: more args than declared.
        assert!(parse_type_name("Ns.A`1[[Ns.X],[Ns.Y]]", ScopeRef::ThisModule).is_err());
        // Arity suffix without argument list at all.
        assert!(parse_type_name("Ns.List`1", ScopeRef::ThisModule).is_err());
        // Trailing garbage.
        assert!(parse_type_name("System.Int32]", ScopeRef::ThisModule).is_err());
        assert!(parse_type_name("System.Int32 x", ScopeRef::ThisModule).is_err());
        // Empty input.
        assert!(parse_type_name("", ScopeRef::ThisModule).is_err());
        // Unterminated constructs.
        assert!(parse_type_name("Ns.Dict`2[[Ns.A]", ScopeRef::ThisModule).is_err());
        assert!(parse_type_name("System.Int32[0,", ScopeRef::ThisModule).is_err());
    }

    #[test]
    fn modreq_modopt_unsupported() {
        let err = parse_type_name(
            "System.Int32 modreq(System.Runtime.InteropServices.IsVolatile)",
            ScopeRef::ThisModule,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
        assert!(parse_type_name("Ns.T modopt(Ns.M)", ScopeRef::ThisModule).is_err());
    }

    #[test]
    fn whitespace_and_escapes_tolerated() {
        let ty = parse_type_name(
            " System.Collections.Generic.Dictionary`2[ [System.String] , [System.Int32] ] ",
            ScopeRef::ThisModule,
        )
        .unwrap();
        let TypeDesc::GenericInstance { arguments, .. } = ty else {
            panic!("expected GenericInstance")
        };
        assert_eq!(arguments.len(), 2);

        // Escaped delimiters survive inside parts.
        let ty = parse_type_name("Weird\\+Ns.T", ScopeRef::ThisModule).unwrap();
        let TypeDesc::External(ext) = ty else { panic!("expected External") };
        assert_eq!(ext.namespace, "Weird+Ns");
        assert_eq!(ext.name, "T");

        // [*] is a rank-1 multidim array, distinct from [].
        let star = parse_type_name("System.Int32[*]", ScopeRef::ThisModule).unwrap();
        assert!(matches!(star, TypeDesc::Array { .. }));
        let comma = parse_type_name("System.Int32[,]", ScopeRef::ThisModule).unwrap();
        match comma {
            TypeDesc::Array { element, sizes, lobounds } => {
                assert_eq!(*element, external("System", "Int32"));
                assert!(sizes.is_empty() && lobounds.is_empty());
            }
            other => panic!("expected rank-2 Array, got {other:?}"),
        }
    }

    #[test]
    fn nested_generic_arity_sums_across_levels() {
        // Outer`1 + Inner`1 = arity 2 total.
        let ty =
            parse_type_name("Ns.Outer`1+Inner`1[[Ns.A],[Ns.B]]", ScopeRef::ThisModule).unwrap();
        let TypeDesc::GenericInstance { arguments, .. } = ty else {
            panic!("expected GenericInstance")
        };
        assert_eq!(arguments.len(), 2);
        // Mismatch across combined arity fails too.
        assert!(parse_type_name("Ns.Outer`1+Inner`1[[Ns.A]]", ScopeRef::ThisModule).is_err());
    }

    #[test]
    fn nested_generic_argument_types_recurse() {
        let ty = parse_type_name("Ns.Dict`1[[Ns.Inner+A[]]]", ScopeRef::ThisModule).unwrap();
        let TypeDesc::GenericInstance { arguments, .. } = ty else {
            panic!("expected GenericInstance")
        };
        match arguments[0].as_ref() {
            TypeDesc::SzArray(elem) => match elem.as_ref() {
                TypeDesc::External(ext) => {
                    assert_eq!(ext.namespace, "");
                    assert_eq!(ext.name, "A");
                }
                other => panic!("expected External element, got {other:?}"),
            },
            other => panic!("expected SzArray argument, got {other:?}"),
        }
    }
}
