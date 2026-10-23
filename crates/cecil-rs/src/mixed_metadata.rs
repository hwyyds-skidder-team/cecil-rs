//! Append-only metadata used when native code can retain original tokens.
//!
//! Every old table row and heap offset is retained. The table stream is
//! re-encoded from numeric cells after additions, so heap/simple/coded indices
//! can widen without changing their meaning.

use std::cell::RefCell;
use std::collections::HashMap;

use cecil_core::io::ByteWriter;
use cecil_core::{ElementType, Error, Result, TableIndex as T, Token};
use cecil_metadata::tables::{column_kinds, ColumnKind, TableSet, TABLE_COUNT};
use cecil_metadata::MetadataReader;

use crate::model::signature::{put_method_signature, write_type_element, SigContext};
use crate::model::types::*;
use crate::module_def::Module;

type MemberKey = (u64, String, Vec<u8>);

struct State {
    rows: Vec<Vec<Vec<u64>>>,
    strings: Vec<u8>,
    blobs: Vec<u8>,
    string_ids: HashMap<String, u32>,
    blob_ids: HashMap<Vec<u8>, u32>,
    type_refs: HashMap<(u64, String, String), u32>,
    members: HashMap<MemberKey, u32>,
    type_specs: HashMap<Vec<u8>, u32>,
    method_specs: HashMap<(u64, Vec<u8>), u32>,
    standalone: HashMap<Vec<u8>, u32>,
    changed_tables: u64,
}

pub(super) struct MetadataEditor<'m> {
    state: RefCell<State>,
    table_header: [u8; 24],
    original_valid: u64,
    extra_data: u32,
    module: &'m Module,
}

impl<'m> MetadataEditor<'m> {
    pub(super) fn new(md: &MetadataReader<'_>, table: &[u8], module: &'m Module) -> Result<Self> {
        let table_header: [u8; 24] = table
            .get(..24)
            .ok_or_else(|| Error::bad_image("truncated metadata table header"))?
            .try_into()
            .unwrap();
        let original_valid = u64::from_le_bytes(table_header[8..16].try_into().unwrap());
        let mut state = State {
            rows: (0..TABLE_COUNT).map(|_| Vec::new()).collect(),
            strings: md.heaps().strings.data().to_vec(),
            blobs: md.heaps().blob.data().to_vec(),
            string_ids: HashMap::new(),
            blob_ids: HashMap::new(),
            type_refs: HashMap::new(),
            members: HashMap::new(),
            type_specs: HashMap::new(),
            method_specs: HashMap::new(),
            standalone: HashMap::new(),
            changed_tables: 0,
        };
        state.string_ids.insert(String::new(), 0);
        state.blob_ids.insert(Vec::new(), 0);
        for number in 0..TABLE_COUNT {
            let Some(table) = T::from_u8(number as u8) else { continue };
            let Some(kinds) = column_kinds(table) else { continue };
            for rid in 1..=md.row_count(table) {
                let row = md.row(table, rid)?;
                for (&value, kind) in row.iter().zip(kinds) {
                    match kind {
                        ColumnKind::StringIdx => {
                            let string = md.heaps().strings.get(value as u32)?;
                            state.string_ids.entry(string.to_string()).or_insert(value as u32);
                        }
                        ColumnKind::BlobIdx => {
                            let blob = md.heaps().blob.get(value as u32)?;
                            state.blob_ids.entry(blob.to_vec()).or_insert(value as u32);
                        }
                        _ => {}
                    }
                }
                match table {
                    T::TypeRef => {
                        let key = (
                            row[0],
                            md.heaps().strings.get(row[2] as u32)?.to_owned(),
                            md.heaps().strings.get(row[1] as u32)?.to_owned(),
                        );
                        state.type_refs.entry(key).or_insert(rid);
                    }
                    T::MemberRef => {
                        let key = (
                            row[0],
                            md.heaps().strings.get(row[1] as u32)?.to_owned(),
                            md.heaps().blob.get(row[2] as u32)?.to_vec(),
                        );
                        state.members.entry(key).or_insert(rid);
                    }
                    T::TypeSpec => {
                        state
                            .type_specs
                            .entry(md.heaps().blob.get(row[0] as u32)?.to_vec())
                            .or_insert(rid);
                    }
                    T::StandAloneSig => {
                        state
                            .standalone
                            .entry(md.heaps().blob.get(row[0] as u32)?.to_vec())
                            .or_insert(rid);
                    }
                    T::MethodSpec => {
                        state
                            .method_specs
                            .entry((row[0], md.heaps().blob.get(row[1] as u32)?.to_vec()))
                            .or_insert(rid);
                    }
                    _ => {}
                }
                state.rows[number].push(row);
            }
        }
        let extra_at = 24 + original_valid.count_ones() as usize * 4;
        let extra_data = if table_header[6] & 0x40 != 0 {
            u32::from_le_bytes(
                table
                    .get(extra_at..extra_at + 4)
                    .ok_or_else(|| Error::bad_image("truncated metadata ExtraData word"))?
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };
        Ok(Self { state: RefCell::new(state), table_header, original_valid, extra_data, module })
    }

    pub(super) fn row_count(&self, table: T) -> u32 {
        self.state.borrow().rows[table as usize].len() as u32
    }

    pub(super) fn set_cell(&self, table: T, rid: u32, column: usize, value: u64) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let cell = rid
            .checked_sub(1)
            .and_then(|row| state.rows[table as usize].get_mut(row as usize))
            .and_then(|row| row.get_mut(column))
            .ok_or_else(|| Error::argument("metadata edit references an absent cell"))?;
        *cell = value;
        Ok(())
    }

    pub(super) fn intern_string(&self, string: &str) -> Result<u32> {
        self.state.borrow_mut().string(string)
    }

    pub(super) fn append_module_references(&self, original: &Module) -> Result<()> {
        for reference in self.module.assembly_refs.iter().skip(original.assembly_refs.len()) {
            self.assembly_scope(reference)?;
        }
        for name in self.module.module_refs.iter().skip(original.module_refs.len()) {
            self.module_scope(name)?;
        }
        Ok(())
    }

    /// Reserve helper definition rows before encoding any signature referring
    /// to them. Existing rows are never moved; ownership is a contiguous tail.
    pub(super) fn append_helper_definitions(&self, original: &Module) -> Result<()> {
        use cecil_core::flags::{MethodAttributes, TypeAttributes};
        if self.module.types.len() != original.types.len()
            && [T::FieldPtr, T::MethodPtr, T::ParamPtr]
                .iter()
                .any(|&table| self.row_count(table) != 0)
        {
            return Err(Error::unsupported(
                "appending helper definitions to pointer-table metadata requires updating ownership maps",
            ));
        }
        let mut next_field = original.fields.len();
        let mut next_method = original.methods.len();
        for (index, ty) in self.module.types.iter().enumerate().skip(original.types.len()) {
            if ty.declaring_type.is_some()
                || !ty.nested_types.is_empty()
                || !ty.properties.is_empty()
                || !ty.events.is_empty()
                || !ty.generic_parameters.is_empty()
                || !ty.interfaces.is_empty()
                || ty.class_layout.is_some()
                || !ty.custom_attributes.is_empty()
                || !ty.security_declarations.is_empty()
                || ty.attributes.contains(TypeAttributes::INTERFACE)
                || ty.attributes.visibility() > TypeAttributes::PUBLIC.bits()
            {
                return Err(Error::unsupported("new helper types must be top-level non-generic types without auxiliary metadata"));
            }
            for field in &ty.fields {
                if field.index() != next_field {
                    return Err(Error::argument(
                        "helper fields must form a contiguous appended ownership range",
                    ));
                }
                next_field += 1;
            }
            for method in &ty.methods {
                if method.index() != next_method
                    || self
                        .module
                        .methods
                        .get(next_method)
                        .is_none_or(|m| m.declaring_type.index() != index)
                {
                    return Err(Error::argument(
                        "helper methods must form a contiguous appended ownership range",
                    ));
                }
                next_method += 1;
            }
        }
        if next_field != self.module.fields.len() || next_method != self.module.methods.len() {
            return Err(Error::argument(
                "appended definitions must be owned by appended helper types",
            ));
        }
        // Reserve all numeric definition RIDs first, allowing helper signatures
        // and method bodies to refer to later helper definitions.
        {
            let mut state = self.state.borrow_mut();
            for _ in original.types.len()..self.module.types.len() {
                state.add(T::TypeDef, vec![0; 6])?;
            }
            for _ in original.fields.len()..self.module.fields.len() {
                state.add(T::Field, vec![0; 3])?;
            }
            for _ in original.methods.len()..self.module.methods.len() {
                state.add(T::MethodDef, vec![0; 6])?;
            }
        }
        next_field = original.fields.len();
        next_method = original.methods.len();
        for (index, ty) in self.module.types.iter().enumerate().skip(original.types.len()) {
            let name = self.intern_string(&ty.name)?;
            let namespace = self.intern_string(&ty.namespace)?;
            let extends =
                ty.base_type.as_ref().map(|base| self.tdor_cell(base)).transpose()?.unwrap_or(0);
            let row = vec![
                ty.attributes.bits() as u64,
                name as u64,
                namespace as u64,
                extends as u64,
                (next_field + 1) as u64,
                (next_method + 1) as u64,
            ];
            self.state.borrow_mut().rows[T::TypeDef as usize][index] = row;
            next_field += ty.fields.len();
            next_method += ty.methods.len();
        }
        for (index, field) in self.module.fields.iter().enumerate().skip(original.fields.len()) {
            if field.constant.is_some()
                || field.marshal_info.is_some()
                || field.offset.is_some()
                || !field.custom_attributes.is_empty()
                || !field.initial_value.is_empty()
                || field.rva != 0
            {
                return Err(Error::unsupported(
                    "new helper fields cannot carry RVA, layout, constants or annotations",
                ));
            }
            let name = self.intern_string(&field.name)?;
            let mut writer = ByteWriter::new();
            writer.u8(6);
            write_type_element(&field.signature.0, &mut writer, self)?;
            let blob = self.state.borrow_mut().blob(writer.as_slice())?;
            self.state.borrow_mut().rows[T::Field as usize][index] =
                vec![field.attributes.bits() as u64, name as u64, blob as u64];
        }
        for (index, method) in self.module.methods.iter().enumerate().skip(original.methods.len()) {
            if method.impl_attributes.bits() & 3 != 0
                || method
                    .attributes
                    .intersects(MethodAttributes::ABSTRACT | MethodAttributes::PINVOKE_IMPL)
                || method.body.is_none()
                || method.signature.generic_count != 0
                || !method.generic_parameters.is_empty()
                || method.pinvoke.is_some()
                || !method.overrides.is_empty()
                || method.constant.is_some()
                || method.marshal_info.is_some()
                || !method.custom_attributes.is_empty()
                || !method.security_declarations.is_empty()
            {
                return Err(Error::unsupported("new helper methods must be ordinary managed IL methods without auxiliary metadata"));
            }
            if method.parameters.len() != method.signature.parameters.len() {
                return Err(Error::argument(
                    "helper method parameter slots must match signature arity",
                ));
            }
            let name = self.intern_string(&method.name)?;
            let mut writer = ByteWriter::new();
            put_method_signature(&mut writer, &method.signature, self)?;
            let mut state = self.state.borrow_mut();
            let blob = state.blob(writer.as_slice())?;
            let param_start = state.rows[T::Param as usize].len() + 1;
            for (sequence, parameter) in std::iter::once(&method.return_parameter)
                .chain(method.parameters.iter())
                .enumerate()
            {
                if parameter.constant.is_some()
                    || parameter.marshal_info.is_some()
                    || !parameter.custom_attributes.is_empty()
                {
                    return Err(Error::unsupported(
                        "new helper parameter annotations are unsupported",
                    ));
                }
                if sequence == 0 && parameter == &Parameter::default() {
                    continue;
                }
                let name = state.string(&parameter.name)?;
                state.add(
                    T::Param,
                    vec![parameter.attributes.bits() as u64, sequence as u64, name as u64],
                )?;
            }
            state.rows[T::MethodDef as usize][index] = vec![
                0,
                method.impl_attributes.bits() as u64,
                method.attributes.bits() as u64,
                name as u64,
                blob as u64,
                param_start as u64,
            ];
        }
        Ok(())
    }

    fn assembly_scope(&self, reference: &AssemblyNameReference) -> Result<u32> {
        if !reference.custom_attributes.is_empty() {
            // Existing annotated refs are matched below; annotations on new
            // references need CustomAttribute rows, which this writer cannot infer.
            let exists = self
                .module
                .assembly_refs
                .iter()
                .take(self.row_count(T::AssemblyRef) as usize)
                .any(|old| old == reference);
            if !exists {
                return Err(Error::unsupported(
                    "new assembly reference annotations require explicit custom attribute emission",
                ));
            }
        }
        let mut state = self.state.borrow_mut();
        let name = state.string(&reference.name)?;
        let culture = state.string(reference.culture.as_deref().unwrap_or(""))?;
        let key = state.blob(&reference.public_key_or_token)?;
        let hash = state.blob(&reference.hash)?;
        let row = vec![
            reference.version.major as u64,
            reference.version.minor as u64,
            reference.version.build as u64,
            reference.version.revision as u64,
            reference.attributes.bits() as u64,
            key as u64,
            name as u64,
            culture as u64,
            hash as u64,
        ];
        // Compare logical payloads, since old duplicate heap entries can have
        // different numeric indices without describing a different scope.
        let found = state.rows[T::AssemblyRef as usize].iter().position(|old| {
            old[..5] == row[..5]
                && state.string_value(old[6] as u32) == reference.name.as_bytes()
                && state.string_value(old[7] as u32)
                    == reference.culture.as_deref().unwrap_or("").as_bytes()
                && state.blob_value(old[5] as u32) == reference.public_key_or_token
                && state.blob_value(old[8] as u32) == reference.hash
        });
        let rid = match found {
            Some(index) => index as u32 + 1,
            None => state.add(T::AssemblyRef, row)?,
        };
        Ok((rid << 2) | 2)
    }

    fn module_scope(&self, name: &str) -> Result<u32> {
        let mut state = self.state.borrow_mut();
        let found = state.rows[T::ModuleRef as usize]
            .iter()
            .position(|row| state.string_value(row[0] as u32) == name.as_bytes());
        let rid = if let Some(index) = found {
            index as u32 + 1
        } else {
            let name = state.string(name)?;
            state.add(T::ModuleRef, vec![name as u64])?
        };
        Ok((rid << 2) | 1)
    }

    fn scope(&self, scope: &ScopeRef) -> Result<u32> {
        match scope {
            ScopeRef::ThisModule => self.definition_token(T::Module, 0).map(|t| t.rid() << 2),
            ScopeRef::OtherModule(name) => self.module_scope(name),
            ScopeRef::Assembly(reference) => self.assembly_scope(reference),
            ScopeRef::Moduleless => Ok(0),
        }
    }

    fn external(&self, external: &ExternalType) -> Result<u32> {
        if external.nesting.len() > 64 {
            return Err(Error::argument("external type nesting exceeds limit"));
        }
        let mut scope = self.scope(&external.scope)?;
        let mut rid = 0;
        for (namespace, name) in external
            .nesting
            .iter()
            .map(|parent| (&parent.namespace, &parent.name))
            .chain(std::iter::once((&external.namespace, &external.name)))
        {
            let key = (scope as u64, namespace.clone(), name.clone());
            let mut state = self.state.borrow_mut();
            rid = if let Some(&rid) = state.type_refs.get(&key) {
                rid
            } else {
                let name = state.string(name)?;
                let namespace = state.string(namespace)?;
                let rid =
                    state.add(T::TypeRef, vec![scope as u64, name as u64, namespace as u64])?;
                state.type_refs.insert(key, rid);
                rid
            };
            scope = (rid << 2) | 3;
        }
        Ok(rid)
    }

    fn type_spec(&self, ty: &TypeDesc) -> Result<u32> {
        let mut writer = ByteWriter::new();
        write_type_element(ty, &mut writer, self)?;
        let bytes = writer.into_vec();
        let mut state = self.state.borrow_mut();
        if let Some(&rid) = state.type_specs.get(&bytes) {
            return Ok(rid);
        }
        let blob = state.blob(&bytes)?;
        let rid = state.add(T::TypeSpec, vec![blob as u64])?;
        state.type_specs.insert(bytes, rid);
        Ok(rid)
    }

    pub(super) fn type_token(&self, ty: &TypeDesc) -> Result<Token> {
        match ty {
            TypeDesc::Def(id) => self.definition_token(T::TypeDef, id.0),
            TypeDesc::External(external) => Ok(Token::new(T::TypeRef, self.external(external)?)),
            _ => Ok(Token::new(T::TypeSpec, self.type_spec(ty)?)),
        }
    }

    pub(super) fn validate_il_token(
        &self,
        kind: cecil_cil::OperandType,
        token: Token,
    ) -> Result<()> {
        use cecil_cil::OperandType;
        let table =
            token.try_table().ok_or_else(|| Error::argument("IL token has an unknown table"))?;
        let state = self.state.borrow();
        let row = token
            .rid()
            .checked_sub(1)
            .and_then(|index| state.rows[table as usize].get(index as usize))
            .ok_or_else(|| Error::argument("IL token references an absent metadata row"))?;
        let member_is_field =
            table == T::MemberRef && state.blob_value(row[2] as u32).first() == Some(&6);
        let is_type = matches!(table, T::TypeDef | T::TypeRef | T::TypeSpec);
        let member_is_method = table == T::MemberRef
            && state
                .blob_value(row[2] as u32)
                .first()
                .is_some_and(|byte| matches!(byte & 0x0f, 0..=5 | 9));
        let is_method = matches!(table, T::MethodDef | T::MethodSpec) || member_is_method;
        let is_field = table == T::Field || member_is_field;
        let valid = match kind {
            OperandType::InlineType => is_type,
            OperandType::InlineMethod => is_method,
            OperandType::InlineField => is_field,
            OperandType::InlineTok => is_type || is_method || is_field,
            OperandType::InlineSig if table == T::StandAloneSig => state
                .blob_value(row[0] as u32)
                .first()
                .is_some_and(|byte| matches!(byte & 0x0f, 0..=5 | 9)),
            _ => false,
        };
        if !valid {
            return Err(Error::argument(
                "IL token table or signature does not match opcode token kind",
            ));
        }
        Ok(())
    }

    pub(super) fn definition_token(&self, table: T, index: u32) -> Result<Token> {
        let rid = index
            .checked_add(1)
            .filter(|rid| *rid <= self.row_count(table))
            .ok_or_else(|| Error::argument("definition handle is outside metadata table"))?;
        Ok(Token::new(table, rid))
    }

    fn member_parent(&self, ty: &TypeDesc) -> Result<u64> {
        let token = self.type_token(ty)?;
        let tag = match token.table() {
            T::TypeDef => 0,
            T::TypeRef => 1,
            T::TypeSpec => 4,
            _ => return Err(Error::argument("invalid MemberRef parent")),
        };
        Ok(((token.rid() as u64) << 3) | tag)
    }

    fn member(&self, parent: u64, name: &str, signature: Vec<u8>) -> Result<Token> {
        let key = (parent, name.to_string(), signature);
        let mut state = self.state.borrow_mut();
        if let Some(&rid) = state.members.get(&key) {
            return Ok(Token::new(T::MemberRef, rid));
        }
        let name = state.string(&key.1)?;
        let blob = state.blob(&key.2)?;
        let rid = state.add(T::MemberRef, vec![parent, name as u64, blob as u64])?;
        state.members.insert(key, rid);
        Ok(Token::new(T::MemberRef, rid))
    }

    pub(super) fn method(&self, method: &MethodRef) -> Result<Token> {
        self.method_at(method, 0)
    }

    fn method_at(&self, method: &MethodRef, depth: usize) -> Result<Token> {
        if depth >= 64 {
            return Err(Error::argument("method reference nesting exceeds limit"));
        }
        match method {
            MethodRef::Def(id) => self.definition_token(T::MethodDef, id.0),
            MethodRef::External(method) => {
                let parent = self.member_parent(&method.parent)?;
                let mut writer = ByteWriter::new();
                put_method_signature(&mut writer, &method.signature, self)?;
                self.member(parent, &method.name, writer.into_vec())
            }
            MethodRef::Spec { method, arguments } => {
                let base = self.method_at(method, depth + 1)?;
                let tag =
                    match base.table() {
                        T::MethodDef => 0,
                        T::MemberRef => 1,
                        _ => return Err(Error::argument(
                            "MethodSpec template must be a method definition or member reference",
                        )),
                    };
                let cell = ((base.rid() as u64) << 1) | tag;
                let mut writer = ByteWriter::new();
                writer.u8(0x0a);
                let length = u32::try_from(arguments.len())
                    .ok()
                    .filter(|n| *n <= 0x1fff_ffff)
                    .ok_or_else(|| Error::argument("too many generic method arguments"))?;
                writer.compressed_u32(length);
                for argument in arguments.iter() {
                    write_type_element(argument, &mut writer, self)?;
                }
                let bytes = writer.into_vec();
                let mut state = self.state.borrow_mut();
                if let Some(&rid) = state.method_specs.get(&(cell, bytes.clone())) {
                    return Ok(Token::new(T::MethodSpec, rid));
                }
                let blob = state.blob(&bytes)?;
                let rid = state.add(T::MethodSpec, vec![cell, blob as u64])?;
                state.method_specs.insert((cell, bytes), rid);
                Ok(Token::new(T::MethodSpec, rid))
            }
        }
    }

    pub(super) fn field(&self, field: &FieldRef) -> Result<Token> {
        match field {
            FieldRef::Def(id) => self.definition_token(T::Field, id.0),
            FieldRef::External(field) => {
                let parent = self.member_parent(&field.parent)?;
                let mut writer = ByteWriter::new();
                writer.u8(6);
                write_type_element(&field.signature.0, &mut writer, self)?;
                self.member(parent, &field.name, writer.into_vec())
            }
        }
    }

    fn standalone(&self, bytes: Vec<u8>) -> Result<Token> {
        let mut state = self.state.borrow_mut();
        if let Some(&rid) = state.standalone.get(&bytes) {
            return Ok(Token::new(T::StandAloneSig, rid));
        }
        let blob = state.blob(&bytes)?;
        let rid = state.add(T::StandAloneSig, vec![blob as u64])?;
        state.standalone.insert(bytes, rid);
        Ok(Token::new(T::StandAloneSig, rid))
    }

    pub(super) fn call_site(&self, signature: &MethodSignature) -> Result<Token> {
        let mut writer = ByteWriter::new();
        put_method_signature(&mut writer, signature, self)?;
        self.standalone(writer.into_vec())
    }

    pub(super) fn locals(&self, locals: &[LocalVariable]) -> Result<Token> {
        if locals.is_empty() {
            return Ok(Token::NIL);
        }
        let count = u32::try_from(locals.len())
            .ok()
            .filter(|n| *n <= u16::MAX as u32 + 1)
            .ok_or_else(|| Error::argument("too many local variable slots"))?;
        let mut writer = ByteWriter::new();
        writer.u8(7);
        writer.compressed_u32(count);
        for (index, local) in locals.iter().enumerate() {
            if local.index as usize != index {
                return Err(Error::argument("local indices must match signature slot order"));
            }
            if local.pinned {
                writer.u8(ElementType::Pinned as u8);
            }
            write_type_element(&local.ty, &mut writer, self)?;
        }
        self.standalone(writer.into_vec())
    }

    pub(super) fn encode_tables(&self, guids_len: usize) -> Result<Vec<u8>> {
        let state = self.state.borrow();
        let mut counts = [0; TABLE_COUNT];
        let mut valid = self.original_valid;
        for (number, rows) in state.rows.iter().enumerate() {
            counts[number] = rows.len() as u32;
            if !rows.is_empty() {
                valid |= 1u64 << number;
            }
        }
        let heap_flags = (self.table_header[6] & !7)
            | u8::from(state.strings.len() > 0xffff)
            | (u8::from(guids_len > 0xffff) << 1)
            | (u8::from(state.blobs.len() > 0xffff) << 2);
        let layout = TableSet::compute_checked(valid, &counts, heap_flags)?;
        let mut writer = ByteWriter::new();
        writer.bytes(&self.table_header[..6]);
        writer.u8(heap_flags);
        writer.u8(self.table_header[7]);
        writer.u64(valid);
        let sorted = u64::from_le_bytes(self.table_header[16..24].try_into().unwrap())
            & !state.changed_tables;
        writer.u64(sorted);
        for (number, &count) in counts.iter().enumerate() {
            if valid >> number & 1 != 0 {
                writer.u32(count);
            }
        }
        // ExtraData is a layout header value, not a row. Keeping its flag while
        // omitting its word would shift every old token's table cell.
        if heap_flags & 0x40 != 0 {
            writer.u32(self.extra_data);
        }
        for (number, rows) in state.rows.iter().enumerate() {
            let Some(table) = T::from_u8(number as u8) else { continue };
            let Some(kinds) = column_kinds(table) else { continue };
            for row in rows {
                for (&cell, kind) in row.iter().zip(kinds) {
                    let width = layout.kind_width(kind);
                    if width < 8 && cell >= 1u64 << (width * 8) {
                        return Err(Error::argument(
                            "metadata cell does not fit final column width",
                        ));
                    }
                    writer.bytes(&cell.to_le_bytes()[..width]);
                }
            }
        }
        Ok(writer.into_vec())
    }

    pub(super) fn heaps(&self) -> (Vec<u8>, Vec<u8>) {
        let state = self.state.borrow();
        (state.strings.clone(), state.blobs.clone())
    }
}

impl SigContext for MetadataEditor<'_> {
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
        let token = self.type_token(ty)?;
        let tag = match token.table() {
            T::TypeDef => 0,
            T::TypeRef => 1,
            T::TypeSpec => 2,
            _ => return Err(Error::argument("invalid TypeDefOrRef token")),
        };
        Ok((token.rid() << 2) | tag)
    }
    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
        // The normal writer's classification policy is deliberately shared:
        // observed VALUETYPE identities, then well-known System structs.
        if let TypeDesc::Def(id) = ty {
            self.definition_token(T::TypeDef, id.0)?;
        }
        let mut builder = cecil_metadata::MetadataBuilder::new("v4.0.30319");
        let result =
            crate::write::token_map::TokenMap::new(&mut builder).is_value_type(ty, self.module);
        result
    }
}

impl State {
    fn string(&mut self, string: &str) -> Result<u32> {
        if string.as_bytes().contains(&0) {
            return Err(Error::argument("metadata name contains NUL"));
        }
        if let Some(&index) = self.string_ids.get(string) {
            return Ok(index);
        }
        if self.strings.is_empty() {
            self.strings.push(0);
        }
        let index = u32::try_from(self.strings.len())
            .map_err(|_| Error::unsupported("metadata string heap exceeds 4 GiB"))?;
        self.strings.extend_from_slice(string.as_bytes());
        self.strings.push(0);
        self.string_ids.insert(string.to_string(), index);
        Ok(index)
    }
    fn blob(&mut self, blob: &[u8]) -> Result<u32> {
        if let Some(&index) = self.blob_ids.get(blob) {
            return Ok(index);
        }
        if self.blobs.is_empty() {
            self.blobs.push(0);
        }
        let length = u32::try_from(blob.len())
            .ok()
            .filter(|n| *n <= 0x1fff_ffff)
            .ok_or_else(|| Error::argument("metadata blob is too large"))?;
        let index = u32::try_from(self.blobs.len())
            .map_err(|_| Error::unsupported("metadata blob heap exceeds 4 GiB"))?;
        let mut prefix = ByteWriter::new();
        prefix.compressed_u32(length);
        self.blobs.extend_from_slice(prefix.as_slice());
        self.blobs.extend_from_slice(blob);
        self.blob_ids.insert(blob.to_vec(), index);
        Ok(index)
    }
    fn add(&mut self, table: T, row: Vec<u64>) -> Result<u32> {
        if self.rows[table as usize].len() >= 0x00ff_ffff {
            return Err(Error::unsupported("metadata table token space exhausted"));
        }
        self.rows[table as usize].push(row);
        self.changed_tables |= 1u64 << table as u8;
        Ok(self.rows[table as usize].len() as u32)
    }
    fn string_value(&self, index: u32) -> &[u8] {
        let bytes = &self.strings[index as usize..];
        let length = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        &bytes[..length]
    }
    fn blob_value(&self, index: u32) -> &[u8] {
        if index == 0 {
            return &[];
        }
        let bytes = &self.blobs[index as usize..];
        let mut reader = cecil_core::io::ByteReader::new(bytes);
        let Ok(length) = reader.compressed_u32() else { return &[] };
        bytes
            .get(reader.position()..reader.position().saturating_add(length as usize))
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cecil_metadata::{parse_root, stream_slice, write_root, MetadataBuilder};
    use std::sync::Arc;

    #[test]
    fn old_rows_survive_heap_coded_and_simple_index_width_changes() {
        let mut original = MetadataBuilder::new("v4.0.30319");
        let name = original.insert_string("Original");
        let method_sig = original.insert_blob(&[0, 0, 1]);
        original.add_row(T::Module, &[0, name as u64, 0, 0, 0]).unwrap();
        for _ in 0..0x3fff {
            original.add_row(T::TypeRef, &[0, name as u64, 0]).unwrap();
        }
        original.add_row(T::TypeDef, &[0, name as u64, 0, (0x3fff << 2) | 1, 1, 1]).unwrap();
        for _ in 0..0xffff {
            original.add_row(T::Param, &[0, 1, name as u64]).unwrap();
        }
        original.add_row(T::MethodDef, &[0, 0, 0, name as u64, method_sig as u64, 0xffff]).unwrap();
        let original = original.finalize();
        let original_md = MetadataReader::parse(&original).unwrap();
        let root = parse_root(&original).unwrap();
        let table =
            stream_slice(&original, root.streams.iter().find(|s| s.name == "#~").unwrap()).unwrap();
        let module = Module::default();
        let editor = MetadataEditor::new(&original_md, table, &module).unwrap();
        let new_type = TypeDesc::External(Arc::new(ExternalType {
            namespace: String::new(),
            name: "Appended".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Moduleless,
        }));
        assert_eq!(editor.type_token(&new_type).unwrap(), Token::new(T::TypeRef, 0x4000));
        editor.intern_string(&"n".repeat(0x1_0000)).unwrap();
        let locals: Vec<_> = (0..=u16::MAX)
            .map(|index| LocalVariable {
                index,
                ty: TypeDesc::Internal("int32".into()),
                pinned: false,
            })
            .collect();
        editor.locals(&locals).unwrap();
        editor.state.borrow_mut().add(T::Param, vec![0, 2, name as u64]).unwrap();
        let table = editor.encode_tables(0).unwrap();
        let (strings, blobs) = editor.heaps();
        let rebuilt =
            write_root("v4.0.30319", &[("#~", &table), ("#Strings", &strings), ("#Blob", &blobs)]);
        let new_md = MetadataReader::parse(&rebuilt).unwrap();
        assert!(new_md.tables().large_string());
        assert!(new_md.tables().large_blob());
        assert_eq!(
            new_md.tables().row_size(T::TypeDef).unwrap(),
            original_md.tables().row_size(T::TypeDef).unwrap() + 6
        );
        assert_eq!(
            new_md.tables().row_size(T::MethodDef).unwrap(),
            original_md.tables().row_size(T::MethodDef).unwrap() + 6
        );
        for table in [T::Module, T::TypeRef, T::TypeDef, T::MethodDef, T::Param] {
            for rid in 1..=original_md.row_count(table) {
                assert_eq!(
                    new_md.row(table, rid).unwrap(),
                    original_md.row(table, rid).unwrap(),
                    "numeric cells must retain the meaning of {table:?} token {rid}"
                );
            }
        }
        assert!(strings.starts_with(original_md.heaps().strings.data()));
        assert!(blobs.starts_with(original_md.heaps().blob.data()));
    }
}
