use super::{AnalysisState, MutationResult};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::{AlterStatisticsActionFact, StatisticsTarget};
use crate::_internal::analysis::graph::DependencyKind;
use crate::_internal::analysis::mutations::{
    AlterStatisticsMutation, AnalyzeMutation, CreateStatisticsMutation, DropStatisticsMutation,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::relation::RelationKind;
use std::collections::HashSet;

/// Smallest statistics target PostgreSQL accepts; -1 means the server default.
const SET_STATISTICS_MIN: i32 = -1;
/// Largest statistics target PostgreSQL stores without clamping.
const SET_STATISTICS_MAX: i32 = 10_000;

impl AnalysisState {
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
        for ty_id in &create.expression_types {
            let mut visited = HashSet::new();
            let ty_str = ty_id.to_string();
            let raw_ty = if ty_id.schema == "pg_catalog"
                || (ty_id.inferred_schema && !self.type_is_present(ty_id))
            {
                ty_id.name.as_str()
            } else {
                ty_str.as_str()
            };
            if self.type_lacks_default_btree_for_statistics(Some(raw_ty), Some(ty_id), &mut visited)
            {
                return MutationResult::conflict(format!(
                    "expression cannot be used in multivariate statistics because its type {raw_ty} has no default btree operator class"
                ));
            }
        }
        for routine_ref in &create.expression_routines {
            let known = self.routine_call_reference_exists(&routine_ref.name);
            if !known
                && (routine_ref.name.schema == "pg_catalog"
                    || self.baseline_covers_family_object(
                        &routine_ref.name,
                        crate::_internal::db::cache::CatalogFamily::Routines,
                    ))
            {
                return MutationResult::conflict(format!(
                    "function {}() does not exist",
                    routine_ref.name
                ));
            }
        }
        self.snapshot_relation(&create.table);
        if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&create.table)
        {
            rel.extended_statistics.insert(
                stats_id.clone(),
                crate::_internal::model::relation::ExtendedStatisticsState {
                    id: stats_id.clone(),
                    kinds: normalized_kinds,
                    columns: tracked_columns,
                    expressions: create.expressions_sql.clone(),
                    target: None,
                    owner: self
                        .local
                        .current_role_known
                        .then(|| ObjectId::new("", &self.local.current_role)),
                },
            );
        }
        if !create.expression_routines.is_empty() || !create.expression_types.is_empty() {
            self.snapshot_graph_full();
            for routine in &create.expression_routines {
                let (referenced, unresolved_name) = match &routine.signature {
                    Some(signature) => (signature.clone(), None),
                    None => (routine.name.clone(), Some(routine.name.clone())),
                };
                self.local
                    .graph
                    .add_edge(crate::_internal::analysis::graph::DependencyEdge::new(
                        stats_id.clone(),
                        referenced,
                        DependencyKind::StatisticsUsesRoutine {
                            table_id: create.table.clone(),
                            unresolved_name,
                        },
                    ));
            }
            for ty in &create.expression_types {
                self.local
                    .graph
                    .add_edge(crate::_internal::analysis::graph::DependencyEdge::new(
                        stats_id.clone(),
                        ty.clone(),
                        DependencyKind::StatisticsUsesType {
                            table_id: create.table.clone(),
                        },
                    ));
            }
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
        if alter.if_exists && !matches!(alter.action, AlterStatisticsActionFact::SetStatistics(_)) {
            return MutationResult::conflict(
                "IF EXISTS is only supported for ALTER STATISTICS ... SET STATISTICS".to_string(),
            );
        }
        if matches!(
            alter.action,
            AlterStatisticsActionFact::SetStatistics(StatisticsTarget::Default)
        ) && self.pg_version_num.unwrap_or(180_000) < 170_000
        {
            return MutationResult::conflict(
                "ALTER STATISTICS ... SET STATISTICS DEFAULT requires PostgreSQL 17 or later"
                    .to_string(),
            );
        }
        let Some(table_id) = owner_table else {
            if alter.if_exists {
                return MutationResult::NoOp;
            }
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
                    rel.extended_statistics.insert(new_id.clone(), stat);
                }
                self.remap_statistics_graph_edges(&alter.id, &new_id);
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
                    rel.extended_statistics.insert(new_id.clone(), stat);
                }
                self.remap_statistics_graph_edges(&alter.id, &new_id);
            }
            AlterStatisticsActionFact::SetStatistics(target) => {
                let next_target = match target {
                    StatisticsTarget::Default => {
                        if self.pg_version_num.unwrap_or(180_000) < 170_000 {
                            return MutationResult::conflict(
                                "ALTER STATISTICS ... SET STATISTICS DEFAULT requires PostgreSQL 17 or later"
                                    .to_string(),
                            );
                        }
                        None
                    }
                    StatisticsTarget::Value(val) => {
                        if *val < SET_STATISTICS_MIN {
                            return MutationResult::conflict(format!(
                                "statistics target {val} is too low"
                            ));
                        }
                        if *val > SET_STATISTICS_MAX {
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
                self.snapshot_relation(&table_id);
                if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                    self.local.relations.get_mut(&table_id)
                    && let Some(stat) = rel.extended_statistics.get_mut(&alter.id)
                {
                    stat.owner = Some(ObjectId::new("", owner_name));
                }
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
        let dropped_stats: Vec<ObjectId> = targets.iter().map(|(_, s)| s.clone()).collect();
        for (table_id, stats_id) in targets {
            self.snapshot_relation(&table_id);
            if let Some(crate::_internal::model::relation::RelationOverlay::Present(rel)) =
                self.local.relations.get_mut(&table_id)
            {
                rel.extended_statistics.remove(&stats_id);
            }
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(dropped_stats.contains(&edge.dependent)
                && matches!(
                    edge.kind,
                    DependencyKind::StatisticsUsesRoutine { .. }
                        | DependencyKind::StatisticsUsesType { .. }
                ))
        });
        MutationResult::Applied
    }

    fn remap_statistics_graph_edges(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        if old_id == new_id {
            return;
        }
        let mut updated = self.local.graph.edges().to_vec();
        let mut any_changed = false;
        for edge in &mut updated {
            if edge.dependent == *old_id
                && matches!(
                    edge.kind,
                    DependencyKind::StatisticsUsesRoutine { .. }
                        | DependencyKind::StatisticsUsesType { .. }
                )
            {
                edge.dependent = new_id.clone();
                any_changed = true;
            }
        }
        if any_changed {
            self.snapshot_graph_full();
            self.local.graph.replace_edges(updated);
        }
    }

    fn parse_analyze_boolean(val: Option<&str>) -> bool {
        match val {
            None => true,
            Some(raw) => matches!(
                raw.trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .to_ascii_lowercase()
                    .as_str(),
                "true" | "false" | "1" | "0" | "on" | "off" | "yes" | "no" | "t" | "f" | "y" | "n"
            ),
        }
    }

    fn parse_buffer_usage_limit_kb(raw: &str) -> Option<u64> {
        let s = raw.trim().trim_matches('\'').trim_matches('"').trim();
        if s == "0" {
            return Some(0);
        }
        let idx = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        if idx == 0 {
            return None;
        }
        let num = s[..idx].parse::<u64>().ok()?;
        let unit = s[idx..].trim();
        let kb = match unit {
            "" | "kB" | "kb" | "KB" => num,
            "B" | "b" => {
                if num % 1024 != 0 {
                    return None;
                }
                num / 1024
            }
            "MB" | "mb" | "Mb" => num.checked_mul(1024)?,
            "GB" | "gb" | "Gb" => num.checked_mul(1024 * 1024)?,
            "TB" | "tb" | "Tb" => num.checked_mul(1024 * 1024 * 1024)?,
            _ => return None,
        };
        if kb == 0 || (128..=16_777_216).contains(&kb) {
            Some(kb)
        } else {
            None
        }
    }

    fn validate_analyze_options(
        &self,
        options: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> Result<(), MutationResult> {
        for opt in options {
            let key = opt.name.to_ascii_lowercase();
            match key.as_str() {
                "verbose" | "skip_locked" => {
                    if !Self::parse_analyze_boolean(opt.value.as_deref()) {
                        return Err(MutationResult::conflict(format!(
                            "{key} requires a Boolean value"
                        )));
                    }
                }
                "buffer_usage_limit" => {
                    if self.pg_version_num.unwrap_or(180_000) < 160_000 {
                        return Err(MutationResult::conflict(format!(
                            "unrecognized ANALYZE option \"{}\"",
                            opt.name
                        )));
                    }
                    let Some(val) = opt.value.as_deref() else {
                        return Err(MutationResult::conflict(
                            "buffer_usage_limit requires a value".to_string(),
                        ));
                    };
                    if Self::parse_buffer_usage_limit_kb(val).is_none() {
                        return Err(MutationResult::conflict(
                            "BUFFER_USAGE_LIMIT option must be 0 or between 128 kB and 16777216 kB"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(MutationResult::conflict(format!(
                        "unrecognized ANALYZE option \"{}\"",
                        opt.name
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_analyze(&mut self, analyze: &AnalyzeMutation) -> MutationResult {
        if let Err(result) = self.validate_analyze_options(&analyze.options) {
            return result;
        }
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
            let mut seen_cols = HashSet::new();
            for col in &target.columns {
                if !seen_cols.insert(col.as_str()) {
                    return MutationResult::conflict(format!(
                        "column \"{col}\" of relation \"{}\" appears more than once",
                        target.table_id.name
                    ));
                }
            }
            if target.table_id.schema == "pg_catalog" {
                if crate::_internal::model::builtin_routine::is_pg_catalog_relation_name(
                    &target.table_id.name,
                ) {
                    if !target.columns.is_empty() {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                    continue;
                }
                return MutationResult::conflict(format!(
                    "relation '{}' does not exist",
                    target.table_id
                ));
            }
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
                None if target.is_unqualified
                    && crate::_internal::model::builtin_routine::is_pg_catalog_relation_name(
                        &target.table_id.name,
                    ) =>
                {
                    if !target.columns.is_empty() {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                }
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
