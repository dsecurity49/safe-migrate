use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::mutations::{
    CastMethodMutation, CreateCastMutation, DropCastMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use std::collections::HashSet;

impl AnalysisState {
    fn is_pseudo_type_name(type_name: &str) -> bool {
        let stripped = type_name.trim().trim_end_matches("[]").trim();
        matches!(
            stripped.to_ascii_lowercase().as_str(),
            "\"any\""
                | "any"
                | "anyarray"
                | "anycompatible"
                | "anycompatiblearray"
                | "anycompatiblemultirange"
                | "anycompatiblenonarray"
                | "anycompatiblerange"
                | "anyelement"
                | "anyenum"
                | "anymultirange"
                | "anynonarray"
                | "anyrange"
                | "cstring"
                | "event_trigger"
                | "fdw_handler"
                | "index_am_handler"
                | "internal"
                | "language_handler"
                | "pg_ddl_command"
                | "record"
                | "table_am_handler"
                | "trigger"
                | "tsm_handler"
                | "unknown"
                | "void"
        )
    }

    fn validate_cast_type(
        &mut self,
        type_name: &str,
        is_source: bool,
    ) -> Result<(), MutationResult> {
        if Self::is_pseudo_type_name(type_name) {
            let side = if is_source { "source" } else { "target" };
            return Err(MutationResult::conflict(format!(
                "{side} data type {type_name} is a pseudo-type"
            )));
        }
        if self.declared_type_resolves(type_name) {
            return Ok(());
        }
        if self.baseline_schemas.is_none()
            && self
                .baseline_coverage
                .has(crate::_internal::db::cache::CatalogFamily::Types)
        {
            return Err(MutationResult::conflict(format!(
                "type \"{type_name}\" does not exist"
            )));
        }
        Err(self.unresolved(EvidenceCode::UnknownObjectState))
    }

    pub(in crate::_internal::analysis::state) fn canonical_cast_type(&self, raw: &str) -> String {
        if let Some(id) = self.resolve_type_reference(raw) {
            return id.to_string();
        }
        let identity = crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
            raw,
            self.builtin_types(),
        );
        if identity.is_unknown() {
            return crate::_internal::model::data_type::ParsedDataType::parse(
                raw,
                self.builtin_types(),
            )
            .to_string();
        }
        identity.render()
    }

    fn unwrap_domain_to_base(&self, mut ty: String) -> String {
        let mut visited = HashSet::new();
        while visited.insert(ty.clone()) {
            let Some(id) = self.resolve_type_reference(&ty) else {
                break;
            };
            let (base_id, is_array) = Self::strip_array_type_id(&id);
            if is_array {
                break;
            }
            let Some(crate::_internal::model::types::TypeOverlay::Present(state)) =
                self.local.types.get(&base_id)
            else {
                break;
            };
            let crate::_internal::model::types::TypeKind::Domain {
                base_type,
                base_type_id,
                ..
            } = &state.kind
            else {
                break;
            };
            if let Some(next_id) = base_type_id {
                ty = next_id.to_string();
            } else {
                ty = self.canonical_cast_type(base_type);
            }
        }
        ty
    }

    fn cast_type_is_binary_coercible(&self, from: &str, to: &str) -> bool {
        let from_canon = self.canonical_cast_type(from);
        let to_canon = self.canonical_cast_type(to);
        if from_canon == to_canon {
            return true;
        }
        let from_base = self.unwrap_domain_to_base(from_canon);
        if from_base == to_canon {
            return true;
        }
        self.local.casts.is_binary_coercible(&from_base, &to_canon)
    }

    fn builtin_base_physical_layout(&self, type_name: &str) -> Option<(i16, bool, char)> {
        match type_name {
            "\"char\"" | "char" | "boolean" | "bool" => Some((1, true, 'c')),
            "smallint" | "int2" => Some((2, true, 's')),
            "integer" | "int4" | "real" | "float4" | "date" | "oid" | "xid" | "cid" | "regproc"
            | "regprocedure" | "regoper" | "regoperator" | "regclass" | "regtype" | "regrole"
            | "regnamespace" | "regconfig" | "regdictionary" | "regcollation" => {
                Some((4, true, 'i'))
            }
            "bigint"
            | "int8"
            | "double precision"
            | "float8"
            | "money"
            | "pg_lsn"
            | "xid8"
            | "time without time zone"
            | "time"
            | "timestamp without time zone"
            | "timestamp"
            | "timestamp with time zone"
            | "timestamptz" => Some((8, true, 'd')),
            "tid" => Some((6, false, 's')),
            "macaddr" => Some((6, false, 'i')),
            "macaddr8" => Some((8, false, 'i')),
            "time with time zone" | "timetz" => Some((12, false, 'd')),
            "uuid" => Some((16, false, 'c')),
            "aclitem" => {
                if self.pg_version_num.unwrap_or(180_000) < 160_000 {
                    Some((12, false, 'i'))
                } else {
                    Some((16, false, 'd'))
                }
            }
            "interval" | "point" => Some((16, false, 'd')),
            "circle" | "line" => Some((24, false, 'd')),
            "box" | "lseg" => Some((32, false, 'd')),
            "name" => Some((64, false, 'c')),
            "path" | "polygon" | "pg_snapshot" | "txid_snapshot" => Some((-1, false, 'd')),
            "bit"
            | "bit varying"
            | "varbit"
            | "bytea"
            | "character"
            | "bpchar"
            | "character varying"
            | "varchar"
            | "cidr"
            | "gtsvector"
            | "inet"
            | "int2vector"
            | "json"
            | "jsonb"
            | "jsonpath"
            | "numeric"
            | "oidvector"
            | "pg_brin_bloom_summary"
            | "pg_brin_minmax_multi_summary"
            | "pg_dependencies"
            | "pg_mcv_list"
            | "pg_ndistinct"
            | "pg_node_tree"
            | "refcursor"
            | "text"
            | "tsquery"
            | "tsvector"
            | "xml" => Some((-1, false, 'i')),
            _ => None,
        }
    }

    fn validate_binary_compatible_cast_type(
        &self,
        type_name: &str,
    ) -> Result<Option<(i16, bool, char)>, MutationResult> {
        let parsed = crate::_internal::model::data_type::ParsedDataType::parse(
            type_name,
            self.builtin_types(),
        );
        if parsed.array_dimensions > 0
            || type_name.ends_with("[]")
            || matches!(type_name, "int2vector" | "oidvector")
        {
            return Err(MutationResult::conflict(
                "array data types are not binary-compatible".to_string(),
            ));
        }
        if let Some(id) = self.resolve_type_reference(type_name) {
            if let Some(crate::_internal::model::relation::RelationOverlay::Present(_)) =
                self.local.relations.get(&id)
            {
                return Err(MutationResult::conflict(
                    "composite data types are not binary-compatible".to_string(),
                ));
            }
            if let Some(crate::_internal::model::types::TypeOverlay::Present(state)) =
                self.local.types.get(&id)
            {
                return match &state.kind {
                    crate::_internal::model::types::TypeKind::Composite { .. } => {
                        Err(MutationResult::conflict(
                            "composite data types are not binary-compatible".to_string(),
                        ))
                    }
                    crate::_internal::model::types::TypeKind::Enum { .. } => {
                        Err(MutationResult::conflict(
                            "enum data types are not binary-compatible".to_string(),
                        ))
                    }
                    crate::_internal::model::types::TypeKind::Range { .. }
                    | crate::_internal::model::types::TypeKind::Multirange { .. } => {
                        Err(MutationResult::conflict(
                            "range data types are not binary-compatible".to_string(),
                        ))
                    }
                    crate::_internal::model::types::TypeKind::Domain { .. } => {
                        Err(MutationResult::conflict(
                            "domain data types must not be marked binary-compatible".to_string(),
                        ))
                    }
                    crate::_internal::model::types::TypeKind::Base { options, .. } => {
                        if options.element.is_some()
                            && options.subscript.as_deref().is_some_and(|sub| {
                                sub.trim()
                                    .trim_start_matches("pg_catalog.")
                                    .starts_with("array_subscript_handler")
                            })
                        {
                            return Err(MutationResult::conflict(
                                "array data types are not binary-compatible".to_string(),
                            ));
                        }
                        if let Some(like_type) = &options.like {
                            let canon_like = self.canonical_cast_type(like_type);
                            return self.validate_binary_compatible_cast_type(&canon_like);
                        }
                        let typlen = match &options.internallength {
                            Some(crate::_internal::model::types::BaseTypeLength::Variable)
                            | None => -1,
                            Some(crate::_internal::model::types::BaseTypeLength::Fixed(n)) => *n,
                        };
                        let typbyval = options.passed_by_value.unwrap_or(false);
                        let typalign = match options
                            .alignment
                            .as_deref()
                            .unwrap_or("int4")
                            .to_ascii_lowercase()
                            .as_str()
                        {
                            "char" => 'c',
                            "int2" => 's',
                            "double" => 'd',
                            _ => 'i',
                        };
                        Ok(Some((typlen, typbyval, typalign)))
                    }
                };
            }
        }
        if let Some(builtin) = parsed.builtin()
            && builtin.category == crate::_internal::model::builtin_type::TypeCategory::Range
        {
            return Err(MutationResult::conflict(
                "range data types are not binary-compatible".to_string(),
            ));
        }
        Ok(self.builtin_base_physical_layout(type_name))
    }

    pub(super) fn apply_create_cast(&mut self, cast: &CreateCastMutation) -> MutationResult {
        if let Err(result) = self.validate_cast_type(&cast.source_type, true) {
            return result;
        }
        if let Err(result) = self.validate_cast_type(&cast.target_type, false) {
            return result;
        }
        let mut num_args = 0usize;
        let entry_method = match &cast.method {
            CastMethodMutation::WithoutFunction => {
                let src_layout = match self.validate_binary_compatible_cast_type(&cast.source_type)
                {
                    Ok(layout) => layout,
                    Err(result) => return result,
                };
                let dst_layout = match self.validate_binary_compatible_cast_type(&cast.target_type)
                {
                    Ok(layout) => layout,
                    Err(result) => return result,
                };
                if let (Some(src), Some(dst)) = (src_layout, dst_layout)
                    && src != dst
                {
                    return MutationResult::conflict(
                        "source and target data types are not physically compatible".to_string(),
                    );
                }
                crate::_internal::model::cast::CastEntryMethod::WithoutFunction
            }
            CastMethodMutation::WithInout => {
                crate::_internal::model::cast::CastEntryMethod::WithInout
            }
            CastMethodMutation::WithFunction(func_id) => {
                match self.local.functions.get(func_id) {
                    Some(crate::_internal::model::function::FunctionOverlay::Present(fn_state)) => {
                        if !matches!(
                            fn_state.routine_kind,
                            crate::_internal::model::function::RoutineKind::Function
                        ) {
                            return MutationResult::conflict(
                                "cast function must be a normal function".to_string(),
                            );
                        }
                        if fn_state.returns_set {
                            return MutationResult::conflict(
                                "cast function must not return a set".to_string(),
                            );
                        }
                        num_args = fn_state.arg_types.len();
                        if !(1..=3).contains(&num_args) {
                            return MutationResult::conflict(
                                "cast function must take one to three arguments".to_string(),
                            );
                        }
                        if !self.cast_type_is_binary_coercible(
                            &cast.source_type,
                            &fn_state.arg_types[0],
                        ) {
                            return MutationResult::conflict(
                                "argument of cast function must match or be binary-coercible from source data type"
                                    .to_string(),
                            );
                        }
                        if num_args > 1
                            && self.canonical_cast_type(&fn_state.arg_types[1]) != "integer"
                        {
                            return MutationResult::conflict(
                                "second argument of cast function must be type integer".to_string(),
                            );
                        }
                        if num_args > 2
                            && self.canonical_cast_type(&fn_state.arg_types[2]) != "boolean"
                        {
                            return MutationResult::conflict(
                                "third argument of cast function must be type boolean".to_string(),
                            );
                        }
                        if !self.cast_type_is_binary_coercible(
                            fn_state.effective_return_type(),
                            &cast.target_type,
                        ) {
                            return MutationResult::conflict(
                                "return data type of cast function must match or be binary-coercible to target data type"
                                    .to_string(),
                            );
                        }
                    }
                    Some(crate::_internal::model::function::FunctionOverlay::Dropped) => {
                        return MutationResult::conflict(format!(
                            "function '{}' does not exist",
                            func_id
                        ));
                    }
                    None if self.baseline_covers_family_object(
                        func_id,
                        crate::_internal::db::cache::CatalogFamily::Routines,
                    ) =>
                    {
                        return MutationResult::conflict(format!(
                            "function '{}' does not exist",
                            func_id
                        ));
                    }
                    None => {
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    }
                }
                crate::_internal::model::cast::CastEntryMethod::WithFunction(Some(func_id.clone()))
            }
        };
        if cast.source_type == cast.target_type && num_args < 2 {
            return MutationResult::conflict(
                "source data type and target data type are the same".to_string(),
            );
        }
        if self
            .local
            .casts
            .has_cast(&cast.source_type, &cast.target_type)
        {
            return MutationResult::conflict(format!(
                "cast from type {} to type {} already exists",
                cast.source_type, cast.target_type
            ));
        }
        if self.baseline_is_available() && !self.local.casts.has_full_cast_coverage() {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        self.snapshot_casts();
        self.local
            .casts
            .insert_cast(crate::_internal::model::cast::CastEntry {
                source: cast.source_type.clone(),
                target: cast.target_type.clone(),
                context: cast.context,
                method: entry_method,
            });
        MutationResult::Applied
    }

    pub(super) fn apply_drop_cast(&mut self, cast: &DropCastMutation) -> MutationResult {
        if !cast.if_exists {
            if let Err(result) = self.validate_cast_type(&cast.source_type, true) {
                return result;
            }
            if let Err(result) = self.validate_cast_type(&cast.target_type, false) {
                return result;
            }
        }
        if self
            .local
            .casts
            .has_cast(&cast.source_type, &cast.target_type)
        {
            if crate::_internal::model::cast_fallback::is_builtin_cast(
                &cast.source_type,
                &cast.target_type,
            ) {
                return MutationResult::conflict(format!(
                    "cannot drop cast from {} to {} because it is required by the database system",
                    cast.source_type, cast.target_type
                ));
            }
            if let Some(result) = self.extension_member_drop_conflict(
                crate::_internal::model::extension::ExtensionMemberKind::Cast,
                &ObjectId::new("", format!("{}->{}", cast.source_type, cast.target_type)),
                "cast",
            ) {
                return result;
            }
            self.snapshot_casts();
            self.local
                .casts
                .remove_cast(&cast.source_type, &cast.target_type);
            return MutationResult::Applied;
        }
        if cast.if_exists {
            return MutationResult::NoOp;
        }
        if self
            .baseline_coverage
            .has(crate::_internal::db::cache::CatalogFamily::Types)
            && self.local.casts.has_full_cast_coverage()
        {
            return MutationResult::conflict(format!(
                "cast from type {} to type {} does not exist",
                cast.source_type, cast.target_type
            ));
        }
        self.unresolved(EvidenceCode::UnknownObjectState)
    }
}
