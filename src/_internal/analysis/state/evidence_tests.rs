use super::*;
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceRecord, EvidenceScope};
use crate::_internal::db::cache::{CatalogFamily, SchemaCoverage};
use crate::_internal::model::index::{IndexOrder, IndexPredicate};

/// Coverage for a hand-built baseline that retrieved `families`.
fn covering(schemas: Option<&[String]>, families: &[CatalogFamily]) -> CatalogCoverage {
    CatalogCoverage::for_families(SchemaCoverage::from_sync_scope(schemas), families)
}

/// Coverage for a hand-built baseline that retrieved the whole catalog.
fn fully_covering(schemas: Option<&[String]>) -> CatalogCoverage {
    covering(schemas, CatalogFamily::ALL)
}

/// A hand-built baseline that retrieved the whole catalog.
fn synced_cache() -> DbCache {
    let mut cache = DbCache::new();
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache
}

/// Whole-catalog coverage minus `family`, to exercise incomplete coverage.
fn covering_except(schemas: Option<&[String]>, family: CatalogFamily) -> CatalogCoverage {
    covering(
        schemas,
        &CatalogFamily::ALL
            .iter()
            .copied()
            .filter(|candidate| *candidate != family)
            .collect::<Vec<_>>(),
    )
}

fn table_with_columns(
    id: ObjectId,
    columns: &[&str],
) -> crate::_internal::model::relation::RelationState {
    let mut relation = crate::_internal::model::relation::RelationState::new(
        id,
        ObjectId::new("", "postgres"),
        0,
        None,
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation.columns = columns
        .iter()
        .map(|name| crate::_internal::model::column::Column {
            name: (*name).to_string(),
            data_type: Some("integer".to_string()),
            type_id: None,
            is_nullable: false,
            default: None,
            avg_width: Some(4),
            default_expr_text: None,
            type_modifier: None,
            storage: None,
            compression: None,
            statistics_target: None,
            options: Default::default(),
            generated: None,
        })
        .collect();
    relation
}

#[test]
fn evidence_added_in_a_transaction_rolls_back_with_confidence() {
    let mut state = AnalysisState::new(DbCache::new());
    state.apply(&Mutation::BeginTransaction, None);
    state.record_evidence(EvidenceRecord::new(
        EvidenceCode::CatalogCoverageIncomplete,
        EvidenceScope::Chain,
    ));

    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert_eq!(state.evidence().len(), 1);

    state.apply(&Mutation::RollbackTransaction, None);
    assert_eq!(state.local.confidence, Confidence::Exact);
    assert!(state.evidence().is_empty());
}

#[test]
fn invalid_transaction_control_records_typed_evidence() {
    let mut state = AnalysisState::new(DbCache::new());
    let result = state.apply(
        &Mutation::Savepoint(crate::_internal::analysis::mutations::SavepointMutation {
            name: "before_change".to_string(),
        }),
        None,
    );

    assert!(matches!(result, MutationResult::Conflict(_)));
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::TransactionStateUnknown)
    );
}

#[test]
fn scoped_schema_lookup_records_unknown_object_evidence() {
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::CreateSchema(
            crate::_internal::analysis::mutations::CreateSchemaMutation {
                name: "outside_scope".to_string(),
                if_not_exists: false,
                authorization: None,
            },
        ),
        None,
    );

    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::UnknownObjectState)
    );
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::UnknownObjectState)
    );
}

#[test]
fn schema_absence_requires_schema_catalog_coverage() {
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    // Everything except the schema catalog, so absence cannot be proven.
    cache.coverage = covering_except(cache.metadata.schemas.as_deref(), CatalogFamily::Schemas);
    let mut state = AnalysisState::new(cache);

    let result = state.apply(
        &Mutation::CreateSchema(
            crate::_internal::analysis::mutations::CreateSchemaMutation {
                name: "public".to_string(),
                if_not_exists: false,
                authorization: None,
            },
        ),
        None,
    );

    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::UnknownObjectState)
    );
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::UnknownObjectState })
    );
}

#[test]
fn role_inherit_option_is_preserved_across_mutations() {
    let mut state = AnalysisState::new(DbCache::new());
    let role_id = ObjectId::new("", "no_inherit");
    let create = Mutation::CreateRole(crate::_internal::analysis::mutations::CreateRoleMutation {
        name: role_id.name.clone(),
        inherits: false,
        can_login: false,
    });
    assert_eq!(state.apply(&create, None), MutationResult::Applied);
    let Some(crate::_internal::model::role::RoleOverlay::Present(role)) =
        state.local.roles.get(&role_id)
    else {
        panic!("expected role to be present");
    };
    assert!(!role.inherits);

    let alter = Mutation::AlterRole(crate::_internal::analysis::mutations::AlterRoleMutation {
        name: crate::_internal::analysis::facts::RoleFact::Named {
            name: role_id.name.clone(),
            via_legacy_group_syntax: false,
        },
        inherits: Some(true),
    });
    assert_eq!(state.apply(&alter, None), MutationResult::Applied);
    let Some(crate::_internal::model::role::RoleOverlay::Present(role)) =
        state.local.roles.get(&role_id)
    else {
        panic!("expected role to remain present");
    };
    assert!(role.inherits);
}

#[test]
fn relation_absence_requires_relation_catalog_coverage() {
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = covering_except(cache.metadata.schemas.as_deref(), CatalogFamily::Relations);
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::DropTable(crate::_internal::analysis::mutations::DropTable {
            ids: vec![ObjectId::new("public", "missing")],
            if_exists: false,
            cascade: false,
        }),
        None,
    );

    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::UnknownObjectState)
    );
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::UnknownObjectState })
    );
}

#[test]
fn baseline_drop_applies_and_taints_without_dependency_catalog_coverage() {
    let table_id = ObjectId::new("public", "known_table");
    let mut cache = synced_cache();
    cache.insert_baseline(
        table_id.clone(),
        table_with_columns(table_id.clone(), &["id"]),
    );
    cache
        .coverage
        .families
        .remove(&crate::_internal::db::cache::CatalogFamily::Dependencies);
    let mut state = AnalysisState::new(cache);

    let result = state.apply(
        &Mutation::DropTable(crate::_internal::analysis::mutations::DropTable {
            ids: vec![table_id.clone()],
            if_exists: false,
            cascade: false,
        }),
        None,
    );

    // PostgreSQL drops the table regardless of what the baseline loaded.
    // Only the reach of the cascade is open, so the drop applies and the
    // chain stops being exact.
    assert_eq!(result, MutationResult::Applied);
    assert!(!state.relation_is_present(&table_id));
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
    );
}

#[test]
fn scoped_boundary_authority_requires_explicit_completion_marker() {
    let table_id = ObjectId::new("app", "known_table");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    cache.metadata.created_at_unix_secs = Some(1);
    cache.insert_baseline(
        table_id.clone(),
        table_with_columns(table_id.clone(), &["id"]),
    );

    let state = AnalysisState::with_baseline(cache.clone(), true);
    assert!(state.baseline_scoped_family_object(
        &table_id,
        crate::_internal::db::cache::CatalogFamily::Relations
    ));

    cache.metadata.boundary_queries_complete = true;
    let state = AnalysisState::with_baseline(cache, true);
    assert!(!state.baseline_scoped_family_object(
        &table_id,
        crate::_internal::db::cache::CatalogFamily::Relations
    ));
}

#[test]
fn local_drop_cascade_requires_dependency_coverage_for_baseline_dependents() {
    let parent = ObjectId::new("public", "new_parent");
    let child = ObjectId::new("public", "baseline_child");
    let mut cache = synced_cache();
    cache.insert_baseline(
        child.clone(),
        table_with_columns(child.clone(), &["parent_id"]),
    );
    cache
        .coverage
        .families
        .remove(&crate::_internal::db::cache::CatalogFamily::Dependencies);
    let mut state = AnalysisState::new(cache);
    state
        .baseline_foreign_keys
        .insert((child.clone(), "baseline_child_parent_fkey".to_string()));
    state.local.relations.insert(
        parent.clone(),
        RelationOverlay::Present(table_with_columns(parent.clone(), &["id"])),
    );
    state.local.graph.add_edge(DependencyEdge::new(
        child.clone(),
        parent.clone(),
        DependencyKind::ForeignKey {
            constraint_name: Some("baseline_child_parent_fkey".to_string()),
            from_columns: vec!["parent_id".to_string()],
            to_columns: vec!["id".to_string()],
            operator_evidence: None,
            from_generation: 0,
        },
    ));

    let result = state.apply(
        &Mutation::DropTable(crate::_internal::analysis::mutations::DropTable {
            ids: vec![parent],
            if_exists: false,
            cascade: true,
        }),
        None,
    );
    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::CatalogCoverageIncomplete)
    );
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
    );
    assert!(state.relation_is_present(&child));
}

#[test]
fn baseline_sequence_drop_requires_dependency_coverage() {
    let sequence_id = ObjectId::new("public", "known_sequence");
    let mut cache = synced_cache();
    cache.sequences.insert(
        sequence_id.clone(),
        crate::_internal::model::sequence::SequenceState {
            id: sequence_id.clone(),
            owner: ObjectId::new("", "postgres"),
            owned_by: None,
            kind: crate::_internal::model::sequence::SequenceKind::Standalone,
            parameters: Default::default(),
            generation: 0,
        },
    );
    cache
        .coverage
        .families
        .remove(&crate::_internal::db::cache::CatalogFamily::Dependencies);
    let mut state = AnalysisState::new(cache);

    let result = state.apply(
        &Mutation::DropSequence(
            crate::_internal::analysis::mutations::DropSequenceMutation {
                ids: vec![sequence_id.clone()],
                if_exists: false,
                cascade: false,
            },
        ),
        None,
    );
    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::CatalogCoverageIncomplete)
    );
    assert!(matches!(
        state.local.sequences.get(&sequence_id),
        Some(SequenceOverlay::Present(_))
    ));
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
    );
}

#[test]
fn scoped_baseline_sequence_drop_requires_cross_schema_dependency_proof() {
    let sequence_id = ObjectId::new("public", "scoped_sequence");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache.sequences.insert(
        sequence_id.clone(),
        crate::_internal::model::sequence::SequenceState {
            id: sequence_id.clone(),
            owner: ObjectId::new("", "postgres"),
            owned_by: None,
            kind: crate::_internal::model::sequence::SequenceKind::Standalone,
            parameters: Default::default(),
            generation: 0,
        },
    );
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::DropSequence(
            crate::_internal::analysis::mutations::DropSequenceMutation {
                ids: vec![sequence_id.clone()],
                if_exists: false,
                cascade: false,
            },
        ),
        None,
    );
    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::CatalogCoverageIncomplete)
    );
    assert!(matches!(
        state.local.sequences.get(&sequence_id),
        Some(SequenceOverlay::Present(_))
    ));
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
    );
}

#[test]
fn baseline_drop_column_applies_and_taints_without_dependency_coverage() {
    let table_id = ObjectId::new("public", "known_table");
    let mut cache = synced_cache();
    cache.insert_baseline(
        table_id.clone(),
        table_with_columns(table_id.clone(), &["id"]),
    );
    cache
        .coverage
        .families
        .remove(&crate::_internal::db::cache::CatalogFamily::Dependencies);
    let mut state = AnalysisState::new(cache);

    let result = state.apply(
        &Mutation::AlterTable(crate::_internal::analysis::mutations::AlterTable {
            id: table_id.clone(),
            only: false,
            action: crate::_internal::analysis::mutations::AlterTableActionMutation::DropColumn {
                name: "id".to_string(),
                if_exists: false,
                cascade: false,
            },
        }),
        None,
    );
    // PostgreSQL drops the column whatever the baseline could not load; only the
    // exactness of the surrounding state is lost.
    assert_eq!(result, MutationResult::Applied);
    assert!(state.local.relations.get(&table_id).is_some_and(|overlay| {
        matches!(overlay, RelationOverlay::Present(relation) if !relation.has_column("id"))
    }));
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::CatalogCoverageIncomplete })
    );
}

#[test]
fn scoped_baseline_type_drop_applies_and_taints() {
    let type_id = ObjectId::new("public", "known_type");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache.types.insert(
        type_id.clone(),
        crate::_internal::model::types::TypeState {
            id: type_id.clone(),
            generation: 0,
            kind: crate::_internal::model::types::TypeKind::Base { element: None },
        },
    );
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::DropType(crate::_internal::analysis::mutations::DropTypeMutation {
            ids: vec![type_id.clone()],
            if_exists: false,
            cascade: false,
        }),
        None,
    );
    // PostgreSQL drops the type regardless of the proof; only the chain's
    // exactness is lost.
    assert_eq!(result, MutationResult::Applied);
    assert!(matches!(
        state.local.types.get(&type_id),
        Some(crate::_internal::model::types::TypeOverlay::Dropped)
    ));
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
    );
}

#[test]
fn a_reference_through_an_unmodeled_class_still_names_its_schema() {
    // An operator belongs to no modeled family, so it produces no edge; the
    // schema that uses it must still be reported, or widening the scope is
    // never suggested.
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache.external_referencing_schemas = vec!["reporting".to_string()];
    let state = AnalysisState::new(cache);
    assert_eq!(
        state.external_referenced_schemas(),
        vec!["reporting".to_string()]
    );
}

#[test]
fn scoped_baseline_function_drop_requires_cross_schema_dependency_proof() {
    let function_id = ObjectId::new("public", "work(integer)");
    let mut cache = synced_cache();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = fully_covering(cache.metadata.schemas.as_deref());
    cache.functions.insert(
        function_id.clone(),
        crate::_internal::model::function::FunctionState {
            return_type: "integer".to_string(),
            ..crate::_internal::model::function::FunctionState::with_inputs(
                function_id.clone(),
                crate::_internal::model::function::RoutineKind::Function,
                vec!["integer".to_string()],
            )
        },
    );
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::DropFunction(
            crate::_internal::analysis::mutations::DropFunctionMutation {
                signatures: vec![crate::_internal::analysis::facts::FunctionSigFact {
                    name: crate::_internal::ast::identifiers::QualifiedName::new(
                        Some(crate::_internal::ast::identifiers::Ident::new(
                            "public", false,
                        )),
                        crate::_internal::ast::identifiers::Ident::new("work", false),
                    ),
                    params: vec!["integer".to_string()],
                }],
                if_exists: false,
                cascade: false,
            },
        ),
        None,
    );
    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::CatalogCoverageIncomplete)
    );
    assert!(matches!(
        state.local.functions.get(&function_id),
        Some(crate::_internal::model::function::FunctionOverlay::Present(
            _
        ))
    ));
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
    );
}

#[test]
fn routine_cascade_without_known_dependents_applies_the_drop() {
    let id = ObjectId::new("public", "work(integer)");
    let routine = |kind| crate::_internal::model::function::FunctionState {
        return_type: "integer".to_string(),
        ..crate::_internal::model::function::FunctionState::with_inputs(
            id.clone(),
            kind,
            vec!["integer".to_string()],
        )
    };
    let signature = || crate::_internal::analysis::facts::FunctionSigFact {
        name: crate::_internal::ast::identifiers::QualifiedName::new(
            Some(crate::_internal::ast::identifiers::Ident::new(
                "public", false,
            )),
            crate::_internal::ast::identifiers::Ident::new("work", false),
        ),
        params: vec!["integer".to_string()],
    };

    let mut procedure_cache = DbCache::new();
    procedure_cache.functions.insert(
        id.clone(),
        routine(crate::_internal::model::function::RoutineKind::Procedure),
    );
    let mut procedure_state = AnalysisState::new(procedure_cache);
    assert_eq!(
        procedure_state.apply(
            &Mutation::DropProcedure(
                crate::_internal::analysis::mutations::DropProcedureMutation {
                    signatures: vec![signature()],
                    if_exists: false,
                    cascade: true,
                }
            ),
            None,
        ),
        MutationResult::Applied
    );
    assert!(matches!(
        procedure_state.local.functions.get(&id),
        Some(crate::_internal::model::function::FunctionOverlay::Dropped)
    ));

    let mut aggregate_cache = DbCache::new();
    aggregate_cache.functions.insert(
        id.clone(),
        routine(crate::_internal::model::function::RoutineKind::Aggregate),
    );
    let mut aggregate_state = AnalysisState::new(aggregate_cache);
    assert_eq!(
        aggregate_state.apply(
            &Mutation::DropAggregate(
                crate::_internal::analysis::mutations::DropAggregateMutation {
                    signatures: vec![signature()],
                    if_exists: false,
                    cascade: true,
                }
            ),
            None,
        ),
        MutationResult::Applied
    );
    assert!(matches!(
        aggregate_state.local.functions.get(&id),
        Some(crate::_internal::model::function::FunctionOverlay::Dropped)
    ));
}

#[test]
fn concurrent_index_drop_rejects_transaction_and_cascade_forms() {
    let mut state = AnalysisState::new(DbCache::new());
    assert_eq!(
        state.apply(&Mutation::BeginTransaction, None),
        MutationResult::Applied
    );
    let concurrent = Mutation::DropIndex(crate::_internal::analysis::mutations::DropIndex {
        ids: Vec::new(),
        if_exists: true,
        concurrently: true,
        cascade: false,
    });
    assert!(matches!(
        state.apply(&concurrent, None),
        MutationResult::Conflict(_)
    ));

    let mut state = AnalysisState::new(DbCache::new());
    let concurrent_cascade =
        Mutation::DropIndex(crate::_internal::analysis::mutations::DropIndex {
            ids: Vec::new(),
            if_exists: true,
            concurrently: true,
            cascade: true,
        });
    assert!(matches!(
        state.apply(&concurrent_cascade, None),
        MutationResult::Conflict(_)
    ));

    let mut state = AnalysisState::new(DbCache::new());
    assert_eq!(
        state.apply(&Mutation::BeginTransaction, None),
        MutationResult::Applied
    );
    let concurrent_create =
        Mutation::CreateIndex(crate::_internal::analysis::mutations::CreateIndex {
            id: ObjectId::new("public", "idx"),
            table: ObjectId::new("public", "table"),
            if_not_exists: false,
            concurrently: true,
            only: false,
            using_method: None,
            predicate: IndexPredicate::None,
            unique: false,
            nulls_not_distinct: false,
            key_columns: vec!["id".to_string()],
            key_expressions: vec![None],
            key_orders: vec![IndexOrder::Default],
            key_opclasses: vec![None],
            key_collations: vec![None],
            included_columns: Vec::new(),
        });
    assert!(matches!(
        state.apply(&concurrent_create, None),
        MutationResult::Conflict(_)
    ));

    let mut refresh_state = AnalysisState::new(DbCache::new());
    assert_eq!(
        refresh_state.apply(&Mutation::BeginTransaction, None),
        MutationResult::Applied
    );
    let concurrent_refresh = Mutation::RefreshMaterializedView(
        crate::_internal::analysis::mutations::RefreshMaterializedViewMutation {
            id: ObjectId::new("public", "mv"),
            concurrently: true,
            with_no_data: false,
        },
    );
    assert!(matches!(
        refresh_state.apply(&concurrent_refresh, None),
        MutationResult::Conflict(_)
    ));

    let partitioned_table = ObjectId::new("public", "events");
    let mut partition_state = AnalysisState::new(DbCache::new());
    let mut relation = table_with_columns(partitioned_table.clone(), &["id"]);
    relation.partition_type = Some("RANGE".to_string());
    partition_state.local.relations.insert(
        partitioned_table.clone(),
        RelationOverlay::Present(relation),
    );
    let concurrent_partition_index =
        Mutation::CreateIndex(crate::_internal::analysis::mutations::CreateIndex {
            id: ObjectId::new("public", "events_id_idx"),
            table: partitioned_table,
            if_not_exists: false,
            concurrently: true,
            only: false,
            using_method: None,
            predicate: IndexPredicate::None,
            unique: false,
            nulls_not_distinct: false,
            key_columns: vec!["id".to_string()],
            key_expressions: vec![None],
            key_orders: vec![IndexOrder::Default],
            key_opclasses: vec![None],
            key_collations: vec![None],
            included_columns: Vec::new(),
        });
    assert!(matches!(
        partition_state.apply(&concurrent_partition_index, None),
        MutationResult::Conflict(_)
    ));

    let partition_drop_table = ObjectId::new("public", "drop_events");
    let mut partition_drop_state = AnalysisState::new(DbCache::new());
    let mut drop_relation = table_with_columns(partition_drop_table.clone(), &["id"]);
    drop_relation.partition_type = Some("RANGE".to_string());
    partition_drop_state.local.relations.insert(
        partition_drop_table.clone(),
        RelationOverlay::Present(drop_relation),
    );
    let drop_index_id = ObjectId::new("public", "drop_events_id_idx");
    assert_eq!(
        partition_drop_state.apply(
            &Mutation::CreateIndex(crate::_internal::analysis::mutations::CreateIndex {
                id: drop_index_id.clone(),
                table: partition_drop_table,
                if_not_exists: false,
                concurrently: false,
                only: false,
                using_method: None,
                predicate: IndexPredicate::None,
                unique: false,
                nulls_not_distinct: false,
                key_columns: vec!["id".to_string()],
                key_expressions: vec![None],
                key_orders: vec![IndexOrder::Default],
                key_opclasses: vec![None],
                key_collations: vec![None],
                included_columns: Vec::new(),
            }),
            None,
        ),
        MutationResult::Applied
    );
    assert!(matches!(
        partition_drop_state.apply(
            &Mutation::DropIndex(crate::_internal::analysis::mutations::DropIndex {
                ids: vec![drop_index_id],
                if_exists: false,
                concurrently: true,
                cascade: false,
            }),
            None,
        ),
        MutationResult::Conflict(_)
    ));
}

#[test]
fn concurrent_refresh_rejects_unpopulated_materialized_view() {
    let view_id = ObjectId::new("public", "empty_mv");
    let mut cache = synced_cache();
    let mut view = crate::_internal::model::relation::RelationState::new(
        view_id.clone(),
        ObjectId::new("", "postgres"),
        0,
        None,
        RelationKind::MaterializedView,
        Persistence::Permanent,
        0,
    );
    view.is_populated = Some(false);
    cache.insert_baseline(view_id.clone(), view);
    let mut state = AnalysisState::new(cache);
    let result = state.apply(
        &Mutation::RefreshMaterializedView(
            crate::_internal::analysis::mutations::RefreshMaterializedViewMutation {
                id: view_id,
                concurrently: true,
                with_no_data: false,
            },
        ),
        None,
    );
    assert!(matches!(result, MutationResult::Conflict(_)));
}

#[test]
fn stale_generation_edges_do_not_block_or_cascade_after_recreation() {
    let parent = ObjectId::new("public", "parent");
    let child = ObjectId::new("public", "child");
    let view = ObjectId::new("public", "parent_view");
    let mut cache = synced_cache();
    cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
    cache.insert_baseline(
        child.clone(),
        table_with_columns(child.clone(), &["parent_id"]),
    );
    let mut view_state = table_with_columns(view.clone(), &["id"]);
    view_state.kind = RelationKind::View;
    cache.insert_baseline(view.clone(), view_state);
    let mut state = AnalysisState::new(cache);
    state.local.graph.add_edge(DependencyEdge::new(
        child.clone(),
        parent.clone(),
        DependencyKind::ForeignKey {
            constraint_name: Some("child_parent_fkey".to_string()),
            from_columns: vec!["parent_id".to_string()],
            to_columns: vec!["id".to_string()],
            operator_evidence: None,
            from_generation: 41,
        },
    ));
    state.local.graph.add_edge(DependencyEdge::new(
        view.clone(),
        parent.clone(),
        DependencyKind::ViewDependency {
            view_generation: 42,
            referenced_column: None,
        },
    ));

    let closure = state.get_cascade_closure(&parent);
    assert_eq!(closure.dropped_relations, HashSet::from([parent.clone()]));
    assert!(closure.dropped_constraints.is_empty());

    let result = state.apply(
        &Mutation::DropTable(crate::_internal::analysis::mutations::DropTable {
            ids: vec![parent],
            if_exists: false,
            cascade: false,
        }),
        None,
    );
    assert_eq!(result, MutationResult::Applied);
}

#[test]
fn unhydrated_generation_edge_remains_conservative() {
    let parent = ObjectId::new("public", "parent");
    let omitted_view = ObjectId::new("tenant", "parent_view");
    let mut cache = synced_cache();
    cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
    let mut state = AnalysisState::new(cache);
    state.local.graph.add_edge(DependencyEdge::new(
        omitted_view.clone(),
        parent.clone(),
        DependencyKind::ViewDependency {
            view_generation: 7,
            referenced_column: None,
        },
    ));

    let closure = state.get_cascade_closure(&parent);
    assert!(closure.dropped_relations.contains(&omitted_view));
    let result = state.apply(
        &Mutation::DropTable(crate::_internal::analysis::mutations::DropTable {
            ids: vec![parent],
            if_exists: false,
            cascade: true,
        }),
        None,
    );
    assert_eq!(result, MutationResult::Applied);
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| { record.code == EvidenceCode::UnknownObjectState })
    );
}

#[test]
fn stale_trigger_generation_does_not_block_schema_restrict() {
    let mut cache = synced_cache();
    cache.schemas.insert(
        "old_schema".to_string(),
        crate::_internal::model::schema::SchemaState {
            name: "old_schema".to_string(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );
    let mut state = AnalysisState::new(cache);
    let trigger_id = ObjectId::new("other_schema", "table\0stale_trigger");
    state.local.triggers.insert(
        trigger_id.clone(),
        TriggerOverlay::Present(crate::_internal::model::trigger::TriggerState {
            name: "stale_trigger".to_string(),
            id: trigger_id.clone(),
            table_id: ObjectId::new("old_schema", "table"),
            function_id: ObjectId::new("other_schema", "fn()"),
            row_level: true,
            parent_trigger_id: None,
            enabled_mode: crate::_internal::model::trigger::TriggerEnableMode::Origin,
            generation: 0,
        }),
    );
    state.local.graph.add_edge(DependencyEdge::new(
        trigger_id.clone(),
        ObjectId::new("old_schema", "table"),
        DependencyKind::TriggerOnTable {
            trigger_id,
            function_id: ObjectId::new("other_schema", "fn()"),
            trigger_generation: 9,
        },
    ));

    let result = state.apply(
        &Mutation::DropSchema(crate::_internal::analysis::mutations::DropSchemaMutation {
            names: vec!["old_schema".to_string()],
            if_exists: false,
            cascade: false,
        }),
        None,
    );
    assert_eq!(
        result,
        MutationResult::Unresolved(EvidenceCode::UnmodeledState)
    );
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::UnmodeledState)
    );
}

#[test]
fn baseline_constraint_keys_hydrate_into_the_dependency_graph() {
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
    cache.constraints.push(ConstraintState {
        table_id: parent.clone(),
        name: "parent_pkey".to_string(),
        kind: crate::_internal::model::constraint::ConstraintKind::PrimaryKey,
        validated: true,
        definition: None,
        backing_index: None,
    });
    cache
        .constraint_keys
        .push(crate::_internal::db::cache::ConstraintKeyCache {
            table_id: parent.clone(),
            constraint_name: "parent_pkey".to_string(),
            columns: vec!["id".to_string()],
            is_primary: true,
        });

    let state = AnalysisState::new(cache);
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == parent
            && edge.referenced == parent
            && matches!(
                &edge.kind,
                DependencyKind::ConstraintOnRelation {
                    constraint_name,
                    columns,
                    is_primary: true,
                } if constraint_name == "parent_pkey" && columns == &["id"]
            )
    }));
}

#[test]
fn malformed_baseline_fk_operator_evidence_is_tainted_not_claimed_exact() {
    let child = ObjectId::new("public", "child");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(
        child.clone(),
        table_with_columns(child.clone(), &["parent_id"]),
    );
    cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
    cache
        .foreign_keys
        .push(crate::_internal::db::cache::ForeignKeyCache {
            constraint_name: "child_parent_fkey".into(),
            from_table: child.clone(),
            to_table: parent.clone(),
            from_columns: vec!["parent_id".into()],
            to_columns: vec!["id".into()],
            pk_fk_equality_operators: Vec::new(),
            pk_pk_equality_operators: vec!["=".into()],
            fk_fk_equality_operators: vec!["=".into()],
        });

    let state = AnalysisState::with_baseline(cache, true);
    assert_eq!(*state.confidence(), Confidence::Tainted);
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
    );
    assert!(state.local.graph.edges().iter().any(|edge| {
        matches!(
            &edge.kind,
            DependencyKind::ForeignKey {
                operator_evidence: None,
                ..
            }
        )
    }));
}

#[test]
fn complete_baseline_fk_operator_evidence_reaches_graph_edge() {
    let child = ObjectId::new("public", "child");
    let parent = ObjectId::new("public", "parent");
    let mut cache = synced_cache();
    cache.insert_baseline(
        child.clone(),
        table_with_columns(child.clone(), &["parent_id"]),
    );
    cache.insert_baseline(parent.clone(), table_with_columns(parent.clone(), &["id"]));
    cache
        .foreign_keys
        .push(crate::_internal::db::cache::ForeignKeyCache {
            constraint_name: "child_parent_fkey".into(),
            from_table: child.clone(),
            to_table: parent.clone(),
            from_columns: vec!["parent_id".into()],
            to_columns: vec!["id".into()],
            pk_fk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
            pk_pk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
            fk_fk_equality_operators: vec!["pg_catalog.=(integer,integer)".into()],
        });

    let state = AnalysisState::with_baseline(cache, true);
    assert_eq!(*state.confidence(), Confidence::Exact);
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == child
            && edge.referenced == parent
            && matches!(
                &edge.kind,
                DependencyKind::ForeignKey {
                    operator_evidence: Some(evidence),
                    ..
                } if evidence.pk_fk == ["pg_catalog.=(integer,integer)".to_string()]
            )
    }));
}

#[test]
fn try_new_rejects_semantically_invalid_cache_before_hydration() {
    let mut cache = synced_cache();
    cache.schemas.insert(
        "public".into(),
        crate::_internal::model::schema::SchemaState {
            name: "other".into(),
            owner: ObjectId::new("", "postgres"),
            generation: 0,
        },
    );

    let error = match AnalysisState::try_new(cache) {
        Ok(_) => panic!("invalid cache unexpectedly hydrated"),
        Err(error) => error,
    };
    assert!(error.contains("schema cache key 'public'"));
}

#[test]
fn role_catalog_coverage_is_authoritative_without_session_provenance() {
    let mut cache = synced_cache();
    let role = ObjectId::new("", "app_role");
    cache.roles.insert(
        role.clone(),
        crate::_internal::model::role::RoleState {
            id: role,
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.metadata.source_role = None;
    cache.metadata.source_session_role = None;

    let state = AnalysisState::with_baseline(cache, true);
    assert!(state.local.roles_known);
}
