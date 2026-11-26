use super::index_topology::AttachRefusal;
use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{
    AlterStatisticsActionFact, IndexStatisticsColumn, StatisticsTarget,
};
use crate::_internal::analysis::graph::DependencyKind;
use crate::_internal::analysis::mutations::{
    AlterDatabaseMutation, AlterIndexActionMutation, AlterIndexAllInTablespaceMutation,
    AlterIndexMutation, AlterStatisticsMutation, AnalyzeMutation, CastMethodMutation,
    CreateCastMutation, CreateDatabaseMutation, CreateStatisticsMutation, DropCastMutation,
    DropDatabaseMutation, DropStatisticsMutation, LockTableMutation, ReindexTargetMutation, Rename,
    TruncateMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::RelationKind;
use std::collections::HashSet;

/// Smallest statistics target PostgreSQL accepts; -1 means the server default.
const SET_STATISTICS_MIN: i32 = -1;
/// Largest statistics target PostgreSQL stores without clamping.
const SET_STATISTICS_MAX: i32 = 10_000;

/// The database a `REINDEX` form names, or `None` when it names none.
///
/// Both `DATABASE` and `SYSTEM` carry an optional name that PostgreSQL
/// resolves against the session's database, so an omitted name is always the
/// current database and needs no check.
fn reindex_target_database_name(target: &ReindexTargetMutation) -> Option<&str> {
    match target {
        ReindexTargetMutation::Database(name) | ReindexTargetMutation::System(Some(name)) => {
            (!name.is_empty()).then_some(name.as_str())
        }
        _ => None,
    }
}

impl AnalysisState {
    pub(super) fn apply_lock_table(&mut self, lock: &LockTableMutation) -> MutationResult {
        for target in &lock.targets {
            if let Err(result) = self.ensure_relation_target(
                &target.id,
                |kind| *kind == RelationKind::Table,
                format!("locked relation '{}' does not exist", target.id),
                format!("locked relation '{}' is not a table", target.id),
            ) {
                return result;
            }
        }
        // Locks are transaction-scoped runtime state.  Validating each target
        // is exact; retaining them in the schema snapshot would incorrectly
        // make a lock survive COMMIT or ROLLBACK.
        MutationResult::Applied
    }

    pub(super) fn apply_truncate(&mut self, truncate: &TruncateMutation) -> MutationResult {
        for target in &truncate.targets {
            if let Err(result) = self.ensure_relation_target(
                &target.id,
                |kind| kind.is_table_like(),
                format!("truncated relation '{}' does not exist", target.id),
                format!("truncated relation '{}' is not a table", target.id),
            ) {
                return result;
            }
        }
        // Row contents are runtime data rather than schema catalog state. A
        // `RESTART IDENTITY` also resets owned sequence counters, including
        // tables reached through `CASCADE`, which this model does not expand.
        // Forget every owned runtime rather than leave a value that a later
        // bound check could treat as exact.
        if truncate.restart_identity {
            let targets = truncate
                .targets
                .iter()
                .map(|target| &target.id)
                .collect::<HashSet<_>>();
            let owned = self
                .local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    crate::_internal::model::sequence::SequenceOverlay::Present(sequence)
                        if sequence.owned_by.as_ref().is_some_and(|(table, _)| {
                            truncate.cascade || targets.contains(table)
                        }) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            for id in owned {
                self.snapshot_sequence(&id);
                if let Some(crate::_internal::model::sequence::SequenceOverlay::Present(sequence)) =
                    self.local.sequences.get_mut(&id)
                {
                    sequence.runtime =
                        crate::_internal::model::sequence::SequenceRuntime::unknown();
                    sequence.runtime_exact = false;
                }
            }
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        }
        MutationResult::Applied
    }

    pub(super) fn apply_check_timeouts(&mut self) -> MutationResult {
        MutationResult::Applied
    }

    pub(super) fn apply_create_database(
        &mut self,
        _create_database: &CreateDatabaseMutation,
    ) -> MutationResult {
        // Database objects are outside the current-database schema model.
        // Keep the mutation available to database-specific rules, but do not
        // claim an exact catalog state transition.
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_alter_database(
        &mut self,
        _alter_database: &AlterDatabaseMutation,
    ) -> MutationResult {
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    pub(super) fn apply_drop_database(
        &mut self,
        _drop_database: &DropDatabaseMutation,
    ) -> MutationResult {
        self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Chain);
        MutationResult::Applied
    }

    /// Validate a REINDEX target and mark a rebuilt leaf index valid.
    pub(super) fn apply_reindex(
        &mut self,
        target: &Option<ReindexTargetMutation>,
        concurrently: bool,
    ) -> MutationResult {
        let reindex_is_concurrent = concurrently;
        if let Some(target) = target {
            // PostgreSQL gives `REINDEX SCHEMA`, `DATABASE` and `SYSTEM`
            // separate commit points per relation, so none of them can run
            // inside a transaction block. `CONCURRENTLY` is checked first and
            // names the form the user wrote.
            if matches!(
                target,
                ReindexTargetMutation::Database(_)
                    | ReindexTargetMutation::Schema(_)
                    | ReindexTargetMutation::System(_)
            ) {
                let form = match target {
                    ReindexTargetMutation::Schema(_) => "REINDEX SCHEMA",
                    ReindexTargetMutation::System(_) => "REINDEX SYSTEM",
                    _ => "REINDEX DATABASE",
                };
                // `PreventInTransactionBlock` only rejects inside an explicit
                // block, so a statement outside one is legal whatever its form.
                if self.in_transaction() {
                    return MutationResult::conflict(format!(
                        "{form} cannot run inside a transaction block"
                    ));
                }
                // Outside a block PostgreSQL still refuses a concurrent
                // system-catalog reindex, which is the form's own rule rather
                // than a transaction rule.
                if matches!(target, ReindexTargetMutation::System(_)) && reindex_is_concurrent {
                    return MutationResult::conflict(
                        "cannot reindex system catalogs concurrently".to_string(),
                    );
                }
                // `ReindexMultipleTables` resolves both of these forms to
                // `MyDatabaseId` and refuses a name that is not it. Analysis
                // has no session, so the name can only be checked against the
                // configured target; without one it cannot be resolved at all.
                if let Some(named) = reindex_target_database_name(target) {
                    match self.target_database() {
                        // PostgreSQL compares with `strcmp` against the name it
                        // reads from `pg_database`, so the comparison is exact.
                        Some(current) if current != named => {
                            return MutationResult::conflict(format!(
                                "can only reindex the currently open database, not '{named}'"
                            ));
                        }
                        Some(_) => {}
                        None => {
                            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
                        }
                    }
                }
                // The catalog scope of these forms is not modeled, so which
                // relations they touch remains unknown.
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
            }
            // A catalog relation named directly cannot be rebuilt concurrently.
            if matches!(
                target,
                ReindexTargetMutation::Table(_) | ReindexTargetMutation::Index(_)
            ) && reindex_is_concurrent
                && self.target_is_catalog(target)
            {
                return MutationResult::conflict(
                    "cannot reindex system catalogs concurrently".to_string(),
                );
            }
            match target {
                ReindexTargetMutation::Database(_)
                | ReindexTargetMutation::Schema(_)
                | ReindexTargetMutation::System(_) => {}
                ReindexTargetMutation::Table(id) => {
                    if let Err(result) = self.ensure_relation_target(
                        id,
                        // PostgreSQL accepts a table, a materialized view, or a
                        // partitioned table, and refuses anything else.
                        |kind| {
                            // A partitioned table is modeled as a table, so
                            // the kind predicate is the same as PostgreSQL's.
                            matches!(
                                kind,
                                crate::_internal::model::relation::RelationKind::Table
                                    | crate::_internal::model::relation::RelationKind::MaterializedView
                            )
                        },
                        format!("reindexed relation '{}' does not exist", id),
                        format!("\"{}\" is not a table or materialized view", id),
                    ) {
                        return result;
                    }
                    // A partitioned table has no storage of its own, so its
                    // partitions are reindexed across commit points.
                    if self.relation_is_partitioned(id) && self.in_transaction() {
                        return MutationResult::conflict(
                            "REINDEX TABLE cannot run inside a transaction block".to_string(),
                        );
                    }
                }
                ReindexTargetMutation::Index(id) => {
                    if !self.index_is_present(id) {
                        // When the baseline covers indexes for this schema we
                        // can be certain the named index does not exist; return
                        // a hard conflict rather than silently tainting.
                        if self.baseline_covers_family_object(
                            id,
                            crate::_internal::db::cache::CatalogFamily::Indexes,
                        ) {
                            return MutationResult::conflict(format!(
                                "reindexed index '{}' does not exist",
                                id
                            ));
                        }
                        // No baseline coverage — we cannot prove it is absent.
                        self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    } else {
                        // REINDEX rebuilds a broken index; a partitioned parent
                        // only becomes valid once its partitions are attached.
                        self.mark_index_valid(id);
                    }
                }
            }
        } else {
            // Missing target implies parsing issue or unsupported target resolution.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
        }

        // Reindex does not change relation metadata (columns, constraints, etc.) directly.
        // The rule engine checks for concurrency.
        MutationResult::Applied
    }

    pub(super) fn apply_vacuum(
        &mut self,
        _table_id: &Option<ObjectId>,
        _is_full: bool,
    ) -> MutationResult {
        // VACUUM changes physical visibility/storage state and may refresh
        // planner statistics, neither of which is represented in the
        // normalized relation model. Keep the statement available to rules,
        // but do not claim an exact post-VACUUM catalog state.
        self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
        MutationResult::Applied
    }

    /// Apply ALTER INDEX actions and validate reloptions and partition attachments.
    pub(super) fn apply_alter_index(&mut self, alter: &AlterIndexMutation) -> MutationResult {
        // Validate the index exists before applying any actions.
        if !self.index_is_present(&alter.index_id) {
            if alter.if_exists {
                return MutationResult::Applied;
            }
            if self.baseline_covers_family_object(
                &alter.index_id,
                crate::_internal::db::cache::CatalogFamily::Indexes,
            ) {
                return MutationResult::conflict(format!(
                    "index '{}' does not exist",
                    alter.index_id
                ));
            }
            return self.unresolved(EvidenceCode::UnknownObjectState);
        }

        for action in &alter.actions {
            match action {
                AlterIndexActionMutation::RenameTo { new_id } => {
                    let result = self.apply_rename_relation(&Rename {
                        old_id: alter.index_id.clone(),
                        new_id: new_id.clone(),
                    });
                    if !matches!(result, MutationResult::Applied) {
                        return result;
                    }
                }
                // Tablespace and reloptions are physical or advisory metadata
                // not tracked in the schema model, but SET options are still
                // validated against the access method's option table.
                AlterIndexActionMutation::SetTablespace { .. } => {}
                AlterIndexActionMutation::SetOptions { options } => {
                    if let Err(result) = self.validate_index_set_options(&alter.index_id, options) {
                        return result;
                    }
                }
                AlterIndexActionMutation::ResetOptions { options } => {
                    if let Err(result) = Self::reset_reloption_names(options) {
                        return result;
                    }
                }
                AlterIndexActionMutation::SetStatistics { column, target } => {
                    let result =
                        self.apply_alter_index_set_statistics(&alter.index_id, column, target);
                    if !matches!(result, MutationResult::Applied) {
                        return result;
                    }
                }
                AlterIndexActionMutation::AttachPartition { partition_id } => {
                    // The partition index must exist for the attach to succeed.
                    if !self.index_is_present(partition_id) {
                        if self.baseline_covers_family_object(
                            partition_id,
                            crate::_internal::db::cache::CatalogFamily::Indexes,
                        ) {
                            return MutationResult::conflict(format!(
                                "partition index '{}' does not exist",
                                partition_id
                            ));
                        }
                        return self.unresolved(EvidenceCode::UnknownObjectState);
                    }
                    let parent_name = alter.index_id.name.as_str();
                    let child_name = partition_id.name.as_str();
                    match self.index_attach_refusal(&alter.index_id, partition_id) {
                        None => {
                            // The attach path revalidates the parent, including
                            // when the child is already attached to it.
                            self.record_index_partition(&alter.index_id, partition_id);
                            self.validate_partitioned_index(&alter.index_id);
                        }
                        Some(AttachRefusal::AttachedElsewhere) => {
                            return MutationResult::conflict(format!(
                                "cannot attach index \"{child_name}\" as partition of index \"{parent_name}\""
                            ));
                        }
                        Some(AttachRefusal::DuplicateAttachment) => {
                            let partition_table = self
                                .index_table_of(partition_id)
                                .map(|table| table.to_string())
                                .unwrap_or_else(|| child_name.to_string());
                            return MutationResult::conflict(format!(
                                "another index is already attached for partition \"{partition_table}\""
                            ));
                        }
                        Some(AttachRefusal::NotAPartition) => {
                            let parent_table = self
                                .index_table_of(&alter.index_id)
                                .map(|table| table.to_string())
                                .unwrap_or_else(|| alter.index_id.to_string());
                            return MutationResult::conflict(format!(
                                "index \"{child_name}\" is not an index on any partition of table \"{parent_table}\""
                            ));
                        }
                        Some(AttachRefusal::MissingConstraint) => {
                            return MutationResult::conflict(format!(
                                "parent index \"{parent_name}\" has a constraint but partition index \"{child_name}\" does not"
                            ));
                        }
                        Some(AttachRefusal::PrimaryKeyNotNull { column }) => {
                            let partition_table = self
                                .index_table_of(partition_id)
                                .map(|table| table.to_string())
                                .unwrap_or_else(|| child_name.to_string());
                            return MutationResult::conflict(format!(
                                "invalid primary key definition: column \"{column}\" of relation \"{partition_table}\" is not marked NOT NULL"
                            ));
                        }
                        Some(AttachRefusal::DefinitionsDiffer) => {
                            return MutationResult::conflict(format!(
                                "cannot attach index \"{child_name}\" as partition of index \"{parent_name}\": the index definitions do not match"
                            ));
                        }
                        Some(AttachRefusal::EquivalenceUnknown) => {
                            return self.unresolved(EvidenceCode::UnmodeledState);
                        }
                    }
                }
                // Extension dependencies are managed by PostgreSQL's extension
                // machinery, which lives outside the schema catalog model.
                AlterIndexActionMutation::DependsOnExtension { .. }
                | AlterIndexActionMutation::NoDependsOnExtension { .. } => {
                    self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                }
            }
        }

        MutationResult::Applied
    }

    /// PostgreSQL checks the range, then clamps above 10000, then the column.
    pub(super) fn apply_alter_index_set_statistics(
        &mut self,
        index: &ObjectId,
        column: &IndexStatisticsColumn,
        target: &StatisticsTarget,
    ) -> MutationResult {
        let StatisticsTarget::Value(value) = target else {
            return MutationResult::Applied;
        };
        if *value < SET_STATISTICS_MIN {
            return MutationResult::conflict(format!("statistics target {value} is too low"));
        }
        if *value > SET_STATISTICS_MAX {
            // Accepted and stored as 10000, so it does not match what was written.
            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
        } else if self.index_has_expression_keys(index) == Some(false) {
            return MutationResult::conflict(format!(
                "cannot alter statistics on non-expression column \"{column}\" of index \"{index}\""
            ));
        }
        MutationResult::Applied
    }

    /// Whether the index is known to have expression keys, or `None` when that
    /// is not established.
    fn index_has_expression_keys(&self, index: &ObjectId) -> Option<bool> {
        self.local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && edge.dependent == *index
            })
            .and_then(|edge| match &edge.kind {
                DependencyKind::IndexOnRelation { definition, .. } => {
                    // A constraint-backed placeholder records its constraint
                    // columns but not its expression keys, so its shape cannot
                    // establish the answer.
                    if definition.unestablished {
                        return None;
                    }
                    Some(definition.has_expression_keys())
                }
                _ => unreachable!("index lookup matched an IndexOnRelation edge"),
            })
    }

    pub(super) fn apply_alter_index_all_in_tablespace(
        &mut self,
        _all: &AlterIndexAllInTablespaceMutation,
    ) -> MutationResult {
        // Tablespace placement (`pg_class.reltablespace`) is not modeled, so
        // this bulk relocation never changes modeled state. The names stay on
        // the mutation for diagnostics.
        MutationResult::Applied
    }

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

    fn canonical_cast_type(&self, raw: &str) -> String {
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

    fn builtin_base_physical_layout(type_name: &str) -> Option<(i16, bool, char)> {
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
            "aclitem" | "interval" | "point" => Some((16, false, 'd')),
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
                        if options.element.is_some() {
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
        Ok(Self::builtin_base_physical_layout(type_name))
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
                        if !self
                            .cast_type_is_binary_coercible(&fn_state.return_type, &cast.target_type)
                        {
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

    fn is_system_column_name(col: &str) -> bool {
        matches!(col, "ctid" | "xmin" | "xmax" | "cmin" | "cmax" | "tableoid")
    }

    fn builtin_type_lacks_default_btree(type_name: &str) -> bool {
        let base = type_name.trim().trim_end_matches("[]").trim();
        matches!(
            base,
            "aclitem"
                | "box"
                | "cid"
                | "circle"
                | "gtsvector"
                | "int2vector"
                | "json"
                | "jsonpath"
                | "line"
                | "lseg"
                | "path"
                | "pg_brin_bloom_summary"
                | "pg_brin_minmax_multi_summary"
                | "pg_snapshot"
                | "point"
                | "polygon"
                | "refcursor"
                | "txid_snapshot"
                | "xid"
                | "xml"
        )
    }

    fn type_lacks_default_btree_for_statistics(
        &self,
        data_type: Option<&str>,
        type_id: Option<&ObjectId>,
        visited: &mut HashSet<ObjectId>,
    ) -> bool {
        if let Some(id) = type_id {
            let (base_id, _) = Self::strip_array_type_id(id);
            if !visited.insert(base_id.clone()) {
                return false;
            }
            if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                self.local.relations.get(&base_id)
            {
                return rel.columns.iter().any(|col| {
                    self.type_lacks_default_btree_for_statistics(
                        col.data_type.as_deref(),
                        col.type_id.as_ref(),
                        visited,
                    )
                });
            }
            if let Some(crate::_internal::model::types::TypeOverlay::Present(state)) =
                self.local.types.get(&base_id)
            {
                return match &state.kind {
                    crate::_internal::model::types::TypeKind::Domain {
                        base_type,
                        base_type_id,
                        ..
                    } => self.type_lacks_default_btree_for_statistics(
                        Some(base_type),
                        base_type_id.as_ref(),
                        visited,
                    ),
                    crate::_internal::model::types::TypeKind::Composite { fields } => {
                        fields.iter().any(|field| {
                            self.type_lacks_default_btree_for_statistics(
                                Some(&field.data_type),
                                field.data_type_id.as_ref(),
                                visited,
                            )
                        })
                    }
                    crate::_internal::model::types::TypeKind::Base { .. } => self
                        .local
                        .opclasses
                        .default_class(Some(&state.id.name), "btree", &[])
                        .is_none(),
                    crate::_internal::model::types::TypeKind::Enum { .. }
                    | crate::_internal::model::types::TypeKind::Range { .. }
                    | crate::_internal::model::types::TypeKind::Multirange { .. } => false,
                };
            }
        }
        let Some(raw) = data_type else {
            return false;
        };
        if let Some(resolved_id) = self.resolve_type_reference(raw) {
            return self.type_lacks_default_btree_for_statistics(
                Some(raw),
                Some(&resolved_id),
                visited,
            );
        }
        let canon = self.canonical_cast_type(raw);
        Self::builtin_type_lacks_default_btree(&canon)
            || Self::builtin_type_lacks_default_btree(raw)
    }

    pub(super) fn apply_create_statistics(
        &mut self,
        create: &CreateStatisticsMutation,
    ) -> MutationResult {
        if let Err(result) = self.ensure_relation_target(
            &create.table,
            |kind| {
                matches!(
                    kind,
                    RelationKind::Table
                        | RelationKind::ForeignTable
                        | RelationKind::MaterializedView
                )
            },
            format!("relation '{}' does not exist", create.table),
            format!("cannot define statistics for relation '{}'", create.table),
        ) {
            return result;
        }
        let stats_id = match &create.id {
            Some(id) => {
                if let Err(result) = self.ensure_creation_target(id) {
                    return result;
                }
                id.clone()
            }
            None => {
                let mut name_elems = create.columns.clone();
                for _ in 0..create.expression_count {
                    name_elems.push("expr".to_string());
                }
                self.next_generated_statistics_name_avoiding(
                    &create.table.schema,
                    &create.table.name,
                    &name_elems,
                    &HashSet::new(),
                )
            }
        };
        if self.extended_statistics_is_present(&stats_id) {
            if create.if_not_exists {
                return MutationResult::NoOp;
            }
            return MutationResult::conflict(format!(
                "statistics object \"{}\" already exists",
                stats_id
            ));
        }
        let total_dimensions = create.columns.len() + create.expression_count;
        if total_dimensions > 8 {
            return MutationResult::conflict(
                "cannot have more than 8 columns in statistics".to_string(),
            );
        }
        if create.columns.is_empty() && create.expression_count == 1 && !create.kinds.is_empty() {
            return MutationResult::conflict(
                "when building statistics on a single expression, statistics kinds may not be specified"
                    .to_string(),
            );
        }
        for col in create
            .columns
            .iter()
            .chain(create.expression_columns.iter())
        {
            if Self::is_system_column_name(col) {
                return MutationResult::conflict(
                    "statistics creation on system columns is not supported".to_string(),
                );
            }
        }
        if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
            self.local.relations.get(&create.table)
        {
            for col in &create.columns {
                if rel.columns_complete && !rel.has_column(col) {
                    return MutationResult::conflict(format!("column \"{col}\" does not exist"));
                }
                if let Some(col_state) = rel.columns.iter().find(|c| &c.name == col) {
                    if rel.generated_columns.get(col).is_some_and(|g| {
                        matches!(
                            g.kind,
                            crate::_internal::model::relation::GeneratedColumnKind::Virtual
                        )
                    }) {
                        return MutationResult::conflict(
                            "statistics creation on virtual generated columns is not supported"
                                .to_string(),
                        );
                    }
                    let mut visited = HashSet::new();
                    if self.type_lacks_default_btree_for_statistics(
                        col_state.data_type.as_deref(),
                        col_state.type_id.as_ref(),
                        &mut visited,
                    ) {
                        let type_label = col_state.data_type.as_deref().unwrap_or("unknown");
                        return MutationResult::conflict(format!(
                            "column \"{col}\" cannot be used in statistics because its type {type_label} has no default btree operator class"
                        ));
                    }
                }
            }
            for col in &create.expression_columns {
                if rel.columns_complete && !rel.has_column(col) {
                    return MutationResult::conflict(format!("column \"{col}\" does not exist"));
                }
                if rel.generated_columns.get(col).is_some_and(|g| {
                    matches!(
                        g.kind,
                        crate::_internal::model::relation::GeneratedColumnKind::Virtual
                    )
                }) {
                    return MutationResult::conflict(
                        "statistics creation on virtual generated columns is not supported"
                            .to_string(),
                    );
                }
            }
        }
        let mut normalized_kinds = Vec::new();
        if create.kinds.is_empty() {
            if total_dimensions >= 2 {
                for k in ["d", "f", "m"] {
                    normalized_kinds.push(k.to_string());
                }
            }
            if create.expression_count > 0 {
                normalized_kinds.push("e".to_string());
            }
        } else {
            for k in &create.kinds {
                let code = match k.to_ascii_lowercase().as_str() {
                    "ndistinct" => "d",
                    "dependencies" => "f",
                    "mcv" => "m",
                    other => {
                        return MutationResult::conflict(format!(
                            "unrecognized statistics kind \"{other}\""
                        ));
                    }
                };
                if !normalized_kinds.iter().any(|existing| existing == code) {
                    normalized_kinds.push(code.to_string());
                }
            }
            if create.expression_count > 0 && !normalized_kinds.iter().any(|k| k == "e") {
                normalized_kinds.push("e".to_string());
            }
        }
        if total_dimensions < 2 && !(create.columns.is_empty() && create.expression_count == 1) {
            return MutationResult::conflict(
                "extended statistics require at least 2 columns".to_string(),
            );
        }
        let mut seen_cols = HashSet::new();
        for col in &create.columns {
            if !seen_cols.insert(col) {
                return MutationResult::conflict(
                    "duplicate column name in statistics definition".to_string(),
                );
            }
        }
        let mut seen_exprs = HashSet::new();
        for expr in &create.expressions {
            if !seen_exprs.insert(expr) {
                return MutationResult::conflict(
                    "duplicate expression in statistics definition".to_string(),
                );
            }
        }
        let mut tracked_columns = create.columns.clone();
        for col in &create.expression_columns {
            if !tracked_columns.contains(col) {
                tracked_columns.push(col.clone());
            }
        }
        self.snapshot_relation(&create.table);
        if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&create.table)
        {
            rel.extended_statistics.insert(
                stats_id.clone(),
                crate::_internal::model::relation::ExtendedStatisticsState {
                    id: stats_id,
                    kinds: normalized_kinds,
                    columns: tracked_columns,
                    expressions: create.expressions_sql.clone(),
                    target: None,
                },
            );
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_statistics(
        &mut self,
        alter: &AlterStatisticsMutation,
    ) -> MutationResult {
        let owner_table = self.local.relations.iter().find_map(|(table_id, overlay)| {
            let crate::_internal::model::relation::RelationOverlay::Present(rel) = overlay else {
                return None;
            };
            rel.extended_statistics
                .contains_key(&alter.id)
                .then(|| table_id.clone())
        });
        let Some(table_id) = owner_table else {
            if self.baseline_covers_family_object(
                &alter.id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            ) {
                return MutationResult::conflict(format!(
                    "statistics object \"{}\" does not exist",
                    alter.id
                ));
            }
            return self.unresolved(EvidenceCode::UnknownObjectState);
        };
        match &alter.action {
            AlterStatisticsActionFact::RenameTo(new_name) => {
                let new_id = ObjectId::new(&alter.id.schema, new_name);
                if new_id != alter.id && self.extended_statistics_is_present(&new_id) {
                    return MutationResult::conflict(format!(
                        "statistics object \"{}\" already exists",
                        new_id
                    ));
                }
                self.snapshot_relation(&table_id);
                if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&table_id)
                    && let Some(mut stat) = rel.extended_statistics.remove(&alter.id)
                {
                    stat.id = new_id.clone();
                    rel.extended_statistics.insert(new_id, stat);
                }
            }
            AlterStatisticsActionFact::SetSchema(new_schema) => {
                if let Err(result) = self.ensure_schema_target(new_schema) {
                    return result;
                }
                let new_id = ObjectId::new(new_schema, &alter.id.name);
                if new_id != alter.id && self.extended_statistics_is_present(&new_id) {
                    return MutationResult::conflict(format!(
                        "statistics object \"{}\" already exists",
                        new_id
                    ));
                }
                self.snapshot_relation(&table_id);
                if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&table_id)
                    && let Some(mut stat) = rel.extended_statistics.remove(&alter.id)
                {
                    stat.id = new_id.clone();
                    rel.extended_statistics.insert(new_id, stat);
                }
            }
            AlterStatisticsActionFact::SetStatistics(target) => {
                let next_target = match target {
                    StatisticsTarget::Default => None,
                    StatisticsTarget::Value(val) => {
                        if *val < SET_STATISTICS_MIN {
                            return MutationResult::conflict(format!(
                                "statistics target {val} is too low"
                            ));
                        }
                        if *val > SET_STATISTICS_MAX {
                            self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
                            Some(SET_STATISTICS_MAX)
                        } else if *val == -1 {
                            None
                        } else {
                            Some(*val)
                        }
                    }
                };
                self.snapshot_relation(&table_id);
                if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&table_id)
                    && let Some(stat) = rel.extended_statistics.get_mut(&alter.id)
                {
                    stat.target = next_target;
                }
            }
            AlterStatisticsActionFact::OwnerTo(owner) => {
                let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                    return self.unresolved(EvidenceCode::UnresolvedReference);
                };
                if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
                    return MutationResult::conflict(format!("role '{owner_name}' does not exist"));
                }
                if known && !self.local.roles_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
                self.taint(EvidenceCode::UnmodeledState, EvidenceScope::Statement);
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_statistics(
        &mut self,
        drop: &DropStatisticsMutation,
    ) -> MutationResult {
        let mut targets: Vec<(ObjectId, ObjectId)> = Vec::new();
        for stats_id in &drop.ids {
            let owner_table = self.local.relations.iter().find_map(|(table_id, overlay)| {
                let crate::_internal::model::relation::RelationOverlay::Present(rel) = overlay
                else {
                    return None;
                };
                rel.extended_statistics
                    .contains_key(stats_id)
                    .then(|| table_id.clone())
            });
            match owner_table {
                Some(table_id) => {
                    if !targets.iter().any(|(_, s)| s == stats_id) {
                        targets.push((table_id, stats_id.clone()));
                    }
                }
                None if drop.if_exists => {}
                None if self.baseline_covers_family_object(
                    stats_id,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ) =>
                {
                    return MutationResult::conflict(format!(
                        "statistics object \"{}\" does not exist",
                        stats_id
                    ));
                }
                None => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        if targets.is_empty() {
            return MutationResult::NoOp;
        }
        for (table_id, stats_id) in targets {
            self.snapshot_relation(&table_id);
            if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                self.local.relations.get_mut(&table_id)
            {
                rel.extended_statistics.remove(&stats_id);
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_analyze(&mut self, analyze: &AnalyzeMutation) -> MutationResult {
        if analyze.targets.is_empty() {
            let all_tables: Vec<ObjectId> = self
                .local
                .relations
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    crate::_internal::model::relation::RelationOverlay::Present(rel)
                        if matches!(
                            rel.kind,
                            RelationKind::Table
                                | RelationKind::MaterializedView
                                | RelationKind::ForeignTable
                        ) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect();
            for table_id in all_tables {
                self.snapshot_relation(&table_id);
                if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&table_id)
                {
                    rel.last_analyze = Some("in-migration".to_string());
                }
            }
            return MutationResult::Applied;
        }
        let mut analyzable_targets = Vec::new();
        for target in &analyze.targets {
            if self.lookup_shadowed(&target.table_id) {
                return self.unresolved(EvidenceCode::UnknownObjectState);
            }
            match self.local.relations.get(&target.table_id) {
                Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) => {
                    if matches!(
                        rel.kind,
                        RelationKind::Table
                            | RelationKind::MaterializedView
                            | RelationKind::ForeignTable
                    ) {
                        if rel.columns_complete {
                            for col in &target.columns {
                                if !rel.has_column(col) {
                                    return MutationResult::conflict(format!(
                                        "column \"{col}\" of relation \"{}\" does not exist",
                                        target.table_id
                                    ));
                                }
                            }
                        }
                        analyzable_targets.push(target.table_id.clone());
                    }
                }
                Some(crate::_internal::model::relation::RelationOverlay::Dropped) => {
                    return MutationResult::conflict(format!(
                        "relation '{}' does not exist",
                        target.table_id
                    ));
                }
                None if self.sequence_is_present(&target.table_id)
                    || self.index_is_present(&target.table_id)
                    || matches!(
                        self.local.types.get(&target.table_id),
                        Some(crate::_internal::model::types::TypeOverlay::Present(
                            crate::_internal::model::types::TypeState {
                                kind: crate::_internal::model::types::TypeKind::Composite { .. },
                                ..
                            }
                        ))
                    ) => {}
                None if self.baseline_covers_family_object(
                    &target.table_id,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ) =>
                {
                    return MutationResult::conflict(format!(
                        "relation '{}' does not exist",
                        target.table_id
                    ));
                }
                None => {
                    return self.unresolved(EvidenceCode::UnknownObjectState);
                }
            }
        }
        for table_id in analyzable_targets {
            self.snapshot_relation(&table_id);
            if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                self.local.relations.get_mut(&table_id)
            {
                rel.last_analyze = Some("in-migration".to_string());
            }
        }
        MutationResult::Applied
    }
}
