//! Canonical managed row allocation without changing the source arena handles.

use cecil_core::{Error, Result, TableIndex, Token};

use crate::model::types::{GenericOwner, Parameter};
use crate::Module;

#[derive(Debug)]
pub(crate) struct DefinitionRows {
    fields: Vec<u32>,
    methods: Vec<u32>,
    properties: Vec<u32>,
    events: Vec<u32>,
    parameters: Vec<u32>,
    generic_parameters: Vec<u32>,
    constraints: Vec<u32>,
    pub(crate) generic_order: Vec<usize>,
}

fn owned_rows(
    count: usize,
    indices: impl Iterator<Item = u32>,
    table: TableIndex,
) -> Result<Vec<u32>> {
    if count > 0x00ff_ffff {
        return Err(Error::argument(format!("{table:?} exceeds metadata token limits")));
    }
    let mut rows = vec![0; count];
    for (index, old) in indices.enumerate() {
        let slot = rows.get_mut(old as usize).ok_or_else(|| {
            Error::argument(format!("{table:?} owner contains an invalid member handle"))
        })?;
        if *slot != 0 {
            return Err(Error::argument(format!("{table:?} member has duplicate owners")));
        }
        *slot = index as u32 + 1;
    }
    if rows.contains(&0) {
        return Err(Error::argument(format!("{table:?} member has no declaring owner")));
    }
    Ok(rows)
}

pub(crate) fn requires_parameter_row(parameter: &Parameter) -> bool {
    !parameter.name.is_empty()
        || !parameter.attributes.is_empty()
        || parameter.constant.is_some()
        || parameter.marshal_info.is_some()
        || !parameter.custom_attributes.is_empty()
}

impl DefinitionRows {
    /// Mixed-mode and sparse standalone symbol models keep source tokens.
    /// Complete managed models validate tokens even when row order is unchanged.
    pub(crate) fn for_symbols(module: &Module) -> Result<Option<Self>> {
        if module.native_image.is_some() {
            return Ok(None);
        }
        // Standalone symbol callers may supply table-RID arenas without any
        // declaring-owner collections. There is no managed emission order to
        // remap in that model. Nonempty owner lists still get full validation.
        let has_members = !module.methods.is_empty()
            || !module.fields.is_empty()
            || !module.properties.is_empty()
            || !module.events.is_empty();
        let has_owners = module.types.iter().any(|ty| {
            !ty.methods.is_empty()
                || !ty.fields.is_empty()
                || !ty.properties.is_empty()
                || !ty.events.is_empty()
        });
        if (has_members && !has_owners) || (!has_members && module.generic_parameters.is_empty()) {
            return Ok(None);
        }
        Ok(Some(Self::new(module)?))
    }

    pub(crate) fn new(module: &Module) -> Result<Self> {
        let fields = owned_rows(
            module.fields.len(),
            module.types.iter().flat_map(|ty| ty.fields.iter().map(|id| id.0)),
            TableIndex::Field,
        )?;
        let methods = owned_rows(
            module.methods.len(),
            module.types.iter().flat_map(|ty| ty.methods.iter().map(|id| id.0)),
            TableIndex::MethodDef,
        )?;
        for (owner, ty) in module.types.iter().enumerate() {
            for id in &ty.methods {
                if module.methods[id.index()].declaring_type.index() != owner {
                    return Err(Error::argument(
                        "method declaring type disagrees with its owner list",
                    ));
                }
            }
        }
        let properties = owned_rows(
            module.properties.len(),
            module.types.iter().flat_map(|ty| ty.properties.iter().map(|id| id.0)),
            TableIndex::Property,
        )?;
        let events = owned_rows(
            module.events.len(),
            module.types.iter().flat_map(|ty| ty.events.iter().map(|id| id.0)),
            TableIndex::Event,
        )?;

        // Param has no arena handles. Its source RID order follows the source
        // method arena, with the same return/parameter row predicate as emission.
        let mut parameter_starts = Vec::with_capacity(module.methods.len() + 1);
        parameter_starts.push(0usize);
        for method in &module.methods {
            let count = usize::from(requires_parameter_row(&method.return_parameter))
                + method.parameters.iter().filter(|p| requires_parameter_row(p)).count();
            parameter_starts.push(parameter_starts.last().unwrap() + count);
        }
        let parameters = owned_rows(
            *parameter_starts.last().unwrap(),
            module
                .types
                .iter()
                .flat_map(|ty| ty.methods.iter())
                .flat_map(|id| parameter_starts[id.index()]..parameter_starts[id.index() + 1])
                .map(|i| i as u32),
            TableIndex::Param,
        )?;

        // ECMA-335 requires GenericParam to be sorted by Owner, then Number.
        // Method owners use the canonical MethodDef RIDs, not their arena IDs.
        let mut generic_order = Vec::with_capacity(module.generic_parameters.len());
        let mut keyed = Vec::with_capacity(module.generic_parameters.len());
        for (index, parameter) in module.generic_parameters.iter().enumerate() {
            let owner = match parameter.owner {
                GenericOwner::Type(id) if id.index() < module.types.len() => (id.0 + 1) << 1,
                GenericOwner::Method(id) => {
                    methods.get(id.index()).copied().map(|rid| (rid << 1) | 1).ok_or_else(|| {
                        Error::argument("generic parameter has an invalid method owner")
                    })?
                }
                _ => return Err(Error::argument("generic parameter has an invalid type owner")),
            };
            keyed.push((owner, parameter.position, index));
        }
        keyed.sort_by_key(|&(owner, position, _)| (owner, position));
        generic_order.extend(keyed.into_iter().map(|(_, _, index)| index));
        let generic_parameters = owned_rows(
            module.generic_parameters.len(),
            generic_order.iter().map(|&i| i as u32),
            TableIndex::GenericParam,
        )?;
        let mut constraint_starts = vec![0usize];
        for parameter in &module.generic_parameters {
            constraint_starts.push(constraint_starts.last().unwrap() + parameter.constraints.len());
        }
        let constraints = owned_rows(
            *constraint_starts.last().unwrap(),
            generic_order
                .iter()
                .flat_map(|&i| constraint_starts[i]..constraint_starts[i + 1])
                .map(|i| i as u32),
            TableIndex::GenericParamConstraint,
        )?;
        Ok(Self {
            fields,
            methods,
            properties,
            events,
            parameters,
            generic_parameters,
            constraints,
            generic_order,
        })
    }

    pub(crate) fn token(&self, token: Token) -> Result<Token> {
        if token.rid() == 0 {
            return Ok(token);
        }
        let rows = match token.table_byte() {
            t if t == TableIndex::Field as u8 => &self.fields,
            t if t == TableIndex::MethodDef as u8 => &self.methods,
            t if t == TableIndex::Property as u8 => &self.properties,
            t if t == TableIndex::Event as u8 => &self.events,
            t if t == TableIndex::Param as u8 => &self.parameters,
            t if t == TableIndex::GenericParam as u8 => &self.generic_parameters,
            t if t == TableIndex::GenericParamConstraint as u8 => &self.constraints,
            _ => return Ok(token),
        };
        let rid = rows.get(token.rid() as usize - 1).copied().ok_or_else(|| {
            Error::argument(format!("definition token {token:?} is outside the source model"))
        })?;
        Ok(Token::new(token.table(), rid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{MethodDefinition, TypeDefinition};

    #[test]
    fn standalone_symbol_arenas_without_owner_lists_keep_source_rids() {
        for types in [Vec::new(), vec![TypeDefinition::default()]] {
            let module =
                Module { types, methods: vec![MethodDefinition::default()], ..Default::default() };
            assert!(DefinitionRows::for_symbols(&module).unwrap().is_none());
            assert!(
                DefinitionRows::new(&module).is_err(),
                "managed writing still validates owners"
            );
        }
    }

    #[test]
    fn partial_or_duplicate_symbol_ownership_is_rejected() {
        let mut module = Module::default();
        let owner = module.add_type(TypeDefinition::default());
        let method = module.add_method(owner, MethodDefinition::default());
        module.methods.push(MethodDefinition::default());
        assert!(DefinitionRows::for_symbols(&module).is_err());
        module.methods.pop();
        module.types[owner.index()].methods.push(method);
        assert!(DefinitionRows::for_symbols(&module).is_err());
    }

    #[test]
    fn complete_symbol_models_remap_owner_grouped_methods() {
        let mut module = Module::default();
        let first = module.add_type(TypeDefinition::default());
        let second = module.add_type(TypeDefinition::default());
        let original = module.add_method(second, MethodDefinition::default());
        let appended = module.add_method(first, MethodDefinition::default());
        let rows = DefinitionRows::for_symbols(&module).unwrap().unwrap();
        assert_eq!(rows.token(Token::new(TableIndex::MethodDef, original.0 + 1)).unwrap().rid(), 2);
        assert_eq!(rows.token(Token::new(TableIndex::MethodDef, appended.0 + 1)).unwrap().rid(), 1);
    }

    #[test]
    fn identity_symbol_models_still_validate_definition_tokens() {
        let mut module = Module::default();
        let owner = module.add_type(TypeDefinition::default());
        module.add_method(owner, MethodDefinition::default());
        let rows = DefinitionRows::for_symbols(&module).unwrap().unwrap();
        assert!(rows.token(Token::new(TableIndex::MethodDef, 2)).is_err());
    }
}
