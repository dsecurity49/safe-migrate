use super::*;

/// Plant a real interrupted-concurrent-detach catalog state: create a parent
/// and child partition, block a `DETACH PARTITION ... CONCURRENTLY` behind a
/// second session's REPEATABLE READ snapshot, wait for PostgreSQL to commit
/// the first internal transaction (`inhdetachpending = true`), then interrupt
/// the detach.  `crash` controls the interruption: `true` terminates the
/// backend (`pg_terminate_backend`), matching how a backend crash leaves the
/// pending row behind; `false` issues a protocol-level query cancel
/// (`cancel_query`).  Either way the committed pending row survives exactly as
/// `FINALIZE` expects it, and the harness synchronizes it via `sync`.
///
/// Returns the identifier of the child relation so callers can assert the
/// hydrated pending edge.
pub(super) fn plant_pending_detach(
    main: &mut Client,
    config: PostgresConfig,
    setup: &PendingDetachSetup,
) -> anyhow::Result<String> {
    let qualified_parent = format!("{}.{}", setup.schema, setup.parent);
    let qualified_child = format!("{}.{}", setup.schema, setup.child);
    main.batch_execute(&format!(
        "CREATE TABLE {qualified_parent} ({column} integer NOT NULL) PARTITION BY {strategy} ({column});
         CREATE TABLE {qualified_child} PARTITION OF {qualified_parent} FOR VALUES {bound};",
        column = setup.column,
        strategy = setup.strategy,
        bound = setup.bound,
    ))?;

    // A second session holds a REPEATABLE READ snapshot, blocking phase 2 of
    // DETACH CONCURRENTLY (the phase-1 catalog row is already committed).
    let mut blocker = config.connect(NoTls)?;
    blocker.batch_execute(&format!(
        "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT * FROM {qualified_parent};"
    ))?;

    let mut detacher = config.connect(NoTls)?;
    let detach_backend: i32 = detacher
        .query_one("SELECT pg_backend_pid()", &[])
        .expect("cannot identify the detacher backend")
        .get(0);
    let cancel = detacher.cancel_token();
    let detach_sql =
        format!("ALTER TABLE {qualified_parent} DETACH PARTITION {qualified_child} CONCURRENTLY");
    let worker = std::thread::spawn(move || detacher.batch_execute(&detach_sql));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut pending = false;
    while Instant::now() < deadline {
        pending = main
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1) AND inhdetachpending)",
                &[&qualified_child],
            )?
            .get(0);
        if pending {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    if setup.crash {
        main.execute("SELECT pg_terminate_backend($1)", &[&detach_backend])?;
    } else {
        cancel.cancel_query(NoTls)?;
    }
    let detached = worker.join().expect("detach worker panicked");
    blocker.batch_execute("ROLLBACK")?;

    if !pending {
        anyhow::bail!("DETACH CONCURRENTLY never reached pending state for {qualified_child}");
    }
    if detached.is_ok() {
        anyhow::bail!("interrupted detach of {qualified_child} completed despite the interruption");
    }
    let sqlstate = detached
        .as_ref()
        .err()
        .and_then(|error| error.as_db_error())
        .map(|db_error| db_error.code().code())
        .unwrap_or_else(|| if setup.crash { "<io>" } else { "<none>" });
    if !matches!(
        sqlstate,
        "57014" | "57P01" | "57P02" | "08P01" | "08006" | "<io>"
    ) {
        anyhow::bail!(
            "interrupted detach of {qualified_child} failed unexpectedly (SQLSTATE {sqlstate}): {error:?}",
            error = detached
        );
    }
    Ok(qualified_child)
}

/// The recorded search path must begin with the schema live PostgreSQL would
/// resolve unqualified names in, or every unqualified fixture compares against
/// the wrong namespace.
pub(super) fn check_recorded_search_path(
    rule: &RuleManifest,
    fixture: &str,
    client: &mut Client,
    cache: &DbCache,
) -> Vec<Mismatch> {
    let live: Vec<String> = match client
        .query_one("SELECT current_schemas(false);", &[])
        .and_then(|row| row.try_get::<_, Vec<String>>(0))
    {
        Ok(path) => path,
        Err(error) => {
            return vec![Mismatch {
                rule_dir: rule.rule_dir.clone(),
                fixture: fixture.to_string(),
                category: MismatchCategory::LiveExecutionFailed,
                root_cause: RootCauseClassification::EnvironmentIssue,
                note: format!("failed to read the live search path: {error}"),
            }];
        }
    };
    let Some(expected) = live.first() else {
        return Vec::new();
    };
    if cache.search_path.first() == Some(expected) {
        return Vec::new();
    }
    vec![Mismatch {
        rule_dir: rule.rule_dir.clone(),
        fixture: fixture.to_string(),
        category: MismatchCategory::BaselineSearchPathMismatch,
        root_cause: RootCauseClassification::SimulatorBug,
        note: format!(
            "baseline records search_path {:?} but live PostgreSQL resolves unqualified names in {expected}",
            cache.search_path
        ),
    }]
}

pub(super) fn check_required_relations(
    rule: &RuleManifest,
    fixture: &str,
    cache: &DbCache,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();
    for relation in &rule.required_relations {
        let (schema, name) = split_qualified_name(relation);
        let object_id = safe_migrate::_internal::ast::identifiers::ObjectId::new(schema, name);
        if !cache.relations.contains_key(&object_id) {
            mismatches.push(Mismatch {
                rule_dir: rule.rule_dir.clone(),
                fixture: fixture.to_string(),
                category: MismatchCategory::BaselineObjectAbsent,
                root_cause: RootCauseClassification::BaselineSetupGap,
                note: format!(
                    "baseline is missing required relation {relation}; check live_tests/differential_baseline.sql"
                ),
            });
        }
    }
    mismatches
}

pub(super) fn check_role_membership_cache(
    rule: &RuleManifest,
    fixture: &str,
    cache: &DbCache,
) -> Vec<Mismatch> {
    let role = |name: &str| {
        cache
            .roles
            .get(&safe_migrate::_internal::ast::identifiers::ObjectId::new(
                "", name,
            ))
    };
    let edge = |ids: &[safe_migrate::_internal::ast::identifiers::ObjectId], target: &str| {
        ids.iter()
            .any(|id| id.schema.is_empty() && id.name == target)
    };
    let active_edges: Vec<&RequiredRoleEdge> = rule
        .required_role_edges
        .iter()
        .filter(|required| {
            required.min_pg_version_num.is_none_or(|minimum| {
                cache
                    .pg_version_num
                    .is_some_and(|version| version >= minimum)
            })
        })
        .collect();
    let required_roles: BTreeSet<&str> = active_edges
        .iter()
        .flat_map(|required| [required.member.as_str(), required.role.as_str()])
        .collect();
    let mut mismatches: Vec<Mismatch> = required_roles
        .into_iter()
        .filter(|name| role(name).is_none())
        .map(|name| Mismatch {
            rule_dir: rule.rule_dir.clone(),
            fixture: fixture.to_string(),
            category: MismatchCategory::BaselineObjectAbsent,
            root_cause: RootCauseClassification::BaselineSetupGap,
            note: format!(
                "baseline is missing required role {name}; check live_tests/differential_baseline.sql"
            ),
        })
        .collect();

    for required in active_edges {
        let (Some(member), Some(_)) = (role(&required.member), role(&required.role)) else {
            continue;
        };
        let matches = match required.kind {
            RequiredRoleEdgeKind::CanSetRoleTo => edge(&member.can_set_role_to, &required.role),
            RequiredRoleEdgeKind::CanAdministerMembership => {
                edge(&member.can_administer_membership, &required.role)
            }
            RequiredRoleEdgeKind::CanInheritFrom => edge(&member.can_inherit_from, &required.role),
            RequiredRoleEdgeKind::MemberOfWithoutSet => {
                edge(&member.member_of, &required.role)
                    && !edge(&member.can_set_role_to, &required.role)
            }
        };
        if !matches {
            mismatches.push(Mismatch {
                rule_dir: rule.rule_dir.clone(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "role {} does not satisfy {:?} edge to {}",
                    required.member, required.kind, required.role
                ),
            });
        }
    }

    mismatches
}

pub(super) fn classify_live_execution_error(error: &postgres::Error) -> RootCauseClassification {
    if error
        .code()
        .is_some_and(|code| matches!(code.code(), "42710" | "42712" | "42723"))
    {
        return RootCauseClassification::BaselineSetupGap;
    }
    match error.code() {
        Some(&postgres::error::SqlState::UNDEFINED_TABLE)
        | Some(&postgres::error::SqlState::UNDEFINED_OBJECT)
        | Some(&postgres::error::SqlState::UNDEFINED_COLUMN)
        | Some(&postgres::error::SqlState::UNDEFINED_FUNCTION)
        | Some(&postgres::error::SqlState::UNDEFINED_SCHEMA) => {
            RootCauseClassification::BaselineSetupGap
        }
        _ => RootCauseClassification::EnvironmentIssue,
    }
}

pub(super) fn format_postgres_error(error: &postgres::Error) -> String {
    let Some(db_error) = error.as_db_error() else {
        return error.to_string();
    };

    let mut message = format!(
        "{} (SQLSTATE {})",
        db_error.message(),
        db_error.code().code()
    );
    if let Some(detail) = db_error.detail() {
        message.push_str(&format!(" detail={detail}"));
    }
    if let Some(hint) = db_error.hint() {
        message.push_str(&format!(" hint={hint}"));
    }
    message
}

pub(super) fn snapshot_live_state(
    client: &mut Client,
    schemas: &[String],
    scope: &[ComparisonScope],
    transaction_is_active: bool,
) -> anyhow::Result<NormalizedState> {
    let cache = if transaction_is_active {
        populate_cache_in_current_transaction(client, Some(schemas))?
    } else {
        populate_cache(client, Some(schemas))?
    };
    let mut state = NormalizedState::default();
    // `format_type` is search_path-sensitive for user-defined types. Resolve
    // each cached column to its catalog identity before projecting it so a
    // fixture that changes search_path cannot turn the same type into two
    // different textual representations.
    let resolved_cache_state = AnalysisState::with_baseline(cache.clone(), true);
    let known_function_ids = cache.functions.keys().cloned().collect::<Vec<_>>();

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, schema) in &cache.schemas {
            state
                .schemas
                .insert(name.clone(), schema.owner.name.clone());
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for (member, role) in &cache.roles {
            for parent in &role.member_of {
                let grantor = cache
                    .role_membership_grantors
                    .iter()
                    .find(|provenance| provenance.member == *member && provenance.role == *parent)
                    .map(|provenance| provenance.grantor.name.clone());
                state.roles.insert(NormalizedRoleMembership {
                    member: member.name.clone(),
                    role: parent.name.clone(),
                    admin: role.can_administer_membership.contains(parent),
                    inherit: role.can_inherit_from.contains(parent),
                    set: role.can_set_role_to.contains(parent),
                    grantor,
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Publications) {
        for (name, publication) in &cache.publications {
            state.publications.insert(
                name.clone(),
                NormalizedPublication {
                    owner: publication.owner.clone(),
                    scope: normalize_publication_scope(&publication.scope),
                    params: normalize_attributes(&publication.params),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, subscription) in &cache.subscriptions {
            state
                .subscriptions
                .insert(name.clone(), normalize_subscription(subscription));
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (id, sequence) in &cache.sequences {
            state.sequences.insert(
                qualified_name(&id.schema, &id.name),
                NormalizedSequence {
                    owner: sequence.owner.name.clone(),
                    owned_by: sequence.owned_by.as_ref().map(|(table, column)| {
                        format!("{}.{}", qualified_name(&table.schema, &table.name), column)
                    }),
                    kind: sequence.kind.clone(),
                    data_type: normalize_data_type(&sequence.parameters.data_type),
                    start_value: sequence.parameters.start_value,
                    increment: sequence.parameters.increment,
                    min_value: sequence.parameters.min_value,
                    max_value: sequence.parameters.max_value,
                    cache_size: sequence.parameters.cache_size,
                    cycle: sequence.parameters.cycle,
                    persistence: normalize_sequence_persistence(sequence.parameters.persistence),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for (id, relation) in &cache.relations {
            for policy in &relation.policies {
                state.policies.insert(NormalizedPolicy {
                    table: qualified_name(&id.schema, &id.name),
                    policy: policy.clone(),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (id, function) in &cache.functions {
            state.functions.insert(
                qualified_name(&id.schema, &id.name),
                normalize_volatility(&function.volatility),
            );
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (id, type_state) in &cache.types {
            state.types.insert(
                qualified_name(&id.schema, &id.name),
                normalize_type_kind(&type_state.kind),
            );
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for (id, relation) in &cache.relations {
            for (grantee, privileges) in &relation.privileges.grants {
                for privilege in privileges {
                    state.privileges.insert(NormalizedPrivilege {
                        table: qualified_name(&id.schema, &id.name),
                        grantee: grantee.name.clone(),
                        privilege: normalize_privilege(*privilege),
                        grantable: relation.privileges.has_grant_option(grantee, *privilege),
                    });
                }
            }
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in &cache.constraints {
            if constraint.kind == ConstraintKind::NotNull {
                continue;
            }
            state.constraints.insert(NormalizedConstraint {
                table: qualified_name(&constraint.table_id.schema, &constraint.table_id.name),
                name: constraint.name.clone(),
                kind: normalize_constraint_kind(constraint.kind),
                validated: constraint.validated,
                definition: normalize_constraint_definition(constraint.definition.as_deref()),
                backing_index: constraint
                    .backing_index
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for trigger in &cache.triggers {
            state.triggers.insert(
                (
                    qualified_name(&trigger.table_id.schema, &trigger.table_id.name),
                    trigger.trigger_id.name.clone(),
                ),
                NormalizedTrigger {
                    function: qualified_name(
                        &trigger.function_id.schema,
                        &trigger.function_id.name,
                    ),
                    enabled_mode: normalize_trigger_mode(trigger.enabled_mode),
                    row_level: trigger.row_level,
                    parent_trigger: trigger
                        .parent_trigger_id
                        .as_ref()
                        .map(|id| qualified_name(&id.schema, &id.name)),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Columns) {
        for (id, relation) in &cache.relations {
            let mut normalized = NormalizedRelation {
                kind: normalize_relation_kind(relation.kind.clone()),
                owner: relation.owner.name.clone(),
                partition_strategy: relation.partition_type.clone(),
                partition_is_default: relation
                    .partition_bound
                    .as_deref()
                    .map(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT")),
                partition_bound: relation.partition_bound.clone(),
                partition_constraint: normalize_partition_constraint(
                    relation.partition_constraint.as_deref(),
                ),
                persistence: normalize_relation_persistence(relation.persistence.clone()),
                tablespace: relation.tablespace.clone(),
                access_method: normalize_access_method(
                    &relation.kind,
                    relation.access_method.as_deref(),
                ),
                cluster_index: relation.cluster_index.clone(),
                row_security: normalize_table_flag(&relation.kind, relation.row_security),
                force_row_security: normalize_table_flag(
                    &relation.kind,
                    relation.force_row_security,
                ),
                replica_identity: normalize_replica_identity(
                    &relation.kind,
                    relation.replica_identity.as_deref(),
                ),
                table_options: relation.table_options.clone(),
                of_type: relation
                    .of_type
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
                rules: relation
                    .rules
                    .iter()
                    .map(|(name, mode)| (name.clone(), format!("{mode:?}")))
                    .collect(),
                columns: BTreeMap::new(),
            };
            if scope.contains(&ComparisonScope::Columns) {
                let resolved_relation = resolved_cache_state.local.relations.get(id);
                for column in &relation.columns {
                    let type_id = resolved_relation.and_then(|overlay| match overlay {
                        RelationOverlay::Present(resolved) => resolved
                            .columns
                            .iter()
                            .find(|resolved_column| resolved_column.name == column.name)
                            .and_then(|resolved_column| resolved_column.type_id.as_ref()),
                        RelationOverlay::Dropped => None,
                    });
                    let data_type = normalize_data_type_with_identity(
                        &column
                            .data_type
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        type_id,
                    );
                    normalized.columns.insert(
                        column.name.clone(),
                        NormalizedColumn {
                            data_type: data_type.clone(),
                            is_nullable: column.is_nullable,
                            has_default: !relation.identity_columns.contains_key(&column.name)
                                && (column.default.is_some() || column.default_expr_text.is_some()),
                            generated: column.generated,
                            generation: normalize_generated_column(
                                relation.generated_columns.get(&column.name),
                                &known_function_ids,
                                &cache.search_path,
                            ),
                            identity_generation: relation
                                .identity_columns
                                .get(&column.name)
                                .map(|generation| format!("{generation:?}")),
                            storage: column.storage.clone(),
                            compression: column.compression.clone(),
                            statistics_target: normalize_statistics_target(
                                column.statistics_target,
                            ),
                            options: column.options.clone(),
                        },
                    );
                }
            }
            state
                .relations
                .insert(qualified_name(&id.schema, &id.name), normalized);
        }
    }

    if scope.contains(&ComparisonScope::Indexes) {
        for index in cache.indexes {
            state.indexes.insert(NormalizedIndex {
                index: qualified_name(&index.index_id.schema, &index.index_id.name),
                table: qualified_name(&index.table_id.schema, &index.table_id.name),
                using_method: index
                    .definition
                    .method
                    .as_ref()
                    .map(|method| method.to_ascii_lowercase()),
                key_columns: index.definition.key_column_names(),
                included_columns: index.definition.included_column_names(),
                has_expression_keys: index.definition.has_expression_keys(),
                has_predicate: index.definition.has_predicate(),
                is_unique: index.definition.unique,
                nulls_not_distinct: index.definition.nulls_not_distinct,
                is_immediate: index.is_immediate,
                is_valid: index.definition.valid,
                is_ready: index.definition.ready,
                is_live: index.definition.live,
                has_default_sort_order: index
                    .definition
                    .keys
                    .iter()
                    .all(|key| key.order == IndexOrder::Default),
                has_default_opclasses: index
                    .definition
                    .keys
                    .iter()
                    .all(|key| matches!(key.opclass, KeyOpclass::Default(_))),
                has_default_collations: index.definition.keys.iter().all(|key| {
                    matches!(
                        key.collation,
                        KeyCollation::NotCollatable | KeyCollation::Derived
                    )
                }),
            });
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (table_id, relation) in &cache.relations {
            for (stats_id, statistics) in &relation.extended_statistics {
                state.extended_statistics.insert(
                    qualified_name(&stats_id.schema, &stats_id.name),
                    NormalizedExtendedStatistics {
                        table: qualified_name(&table_id.schema, &table_id.name),
                        kinds: statistics.kinds.clone(),
                        columns: statistics.columns.clone(),
                        expressions: statistics.expressions.clone(),
                        target: normalize_statistics_target(statistics.target),
                    },
                );
            }
        }
    }

    if scope.contains(&ComparisonScope::ForeignKeys) {
        for fk in cache.foreign_keys {
            state.foreign_keys.insert(NormalizedForeignKey {
                from_table: qualified_name(&fk.from_table.schema, &fk.from_table.name),
                to_table: qualified_name(&fk.to_table.schema, &fk.to_table.name),
                constraint_name: fk.constraint_name,
            });
        }
    }

    if scope.contains(&ComparisonScope::Partitions) {
        let schema_names = schemas.to_vec();
        for row in client.query(
            "
            SELECT
                pn.nspname AS parent_schema,
                pc.relname AS parent_name,
                cn.nspname AS child_schema,
                cc.relname AS child_name,
                cc.relispartition AS is_partition,
                i.inhdetachpending AS detach_pending
            FROM pg_inherits i
            JOIN pg_class pc ON pc.oid = i.inhparent
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN pg_class cc ON cc.oid = i.inhrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            WHERE pn.nspname = ANY($1) AND cn.nspname = ANY($1)
              AND pc.relkind IN ('r', 'p')
              AND cc.relkind IN ('r', 'p')
            ",
            &[&schema_names],
        )? {
            let parent_schema: String = row.get("parent_schema");
            let parent_name: String = row.get("parent_name");
            let child_schema: String = row.get("child_schema");
            let child_name: String = row.get("child_name");
            state.partition_edges.insert((
                qualified_name(&parent_schema, &parent_name),
                qualified_name(&child_schema, &child_name),
                row.get("is_partition"),
                row.get("detach_pending"),
            ));
        }
    }

    if scope.contains(&ComparisonScope::IndexPartitions) {
        let schema_names = schemas.to_vec();
        for row in client.query(
            "
            SELECT
                pn.nspname AS parent_schema,
                pc.relname AS parent_name,
                cn.nspname AS child_schema,
                cc.relname AS child_name
            FROM pg_inherits i
            JOIN pg_class pc ON pc.oid = i.inhparent
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            JOIN pg_class cc ON cc.oid = i.inhrelid
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            WHERE pn.nspname = ANY($1) AND cn.nspname = ANY($1)
              AND pc.relkind = 'I'
              AND cc.relkind IN ('i', 'I')
            ",
            &[&schema_names],
        )? {
            state.index_attachment_edges.insert((
                qualified_name(
                    &row.get::<_, String>("parent_schema"),
                    &row.get::<_, String>("parent_name"),
                ),
                qualified_name(
                    &row.get::<_, String>("child_schema"),
                    &row.get::<_, String>("child_name"),
                ),
            ));
        }
    }

    if scope.contains(&ComparisonScope::ViewDependencies) {
        let schema_names = schemas.to_vec();
        for row in client.query(
            "
            SELECT DISTINCT
                vn.nspname AS view_schema,
                vc.relname AS view_name,
                tn.nspname AS table_schema,
                tc.relname AS table_name
            FROM pg_rewrite rw
            JOIN pg_class vc ON vc.oid = rw.ev_class
            JOIN pg_namespace vn ON vn.oid = vc.relnamespace
            JOIN pg_depend d ON d.objid = rw.oid
            JOIN pg_class tc ON tc.oid = d.refobjid
            JOIN pg_namespace tn ON tn.oid = tc.relnamespace
            WHERE vc.relkind IN ('v', 'm')
              AND vn.nspname = ANY($1)
              AND tn.nspname = ANY($1)
              AND d.deptype = 'n'
              -- PostgreSQL 14/15 expose an internal rewrite-rule self-edge
              -- here. It is not a view-to-relation dependency that the
              -- simulator should model.
              AND tc.oid <> vc.oid
            ",
            &[&schema_names],
        )? {
            let view_schema: String = row.get("view_schema");
            let view_name: String = row.get("view_name");
            let table_schema: String = row.get("table_schema");
            let table_name: String = row.get("table_name");
            state.view_dependencies.insert((
                qualified_name(&view_schema, &view_name),
                qualified_name(&table_schema, &table_name),
            ));
        }
    }

    if scope.contains(&ComparisonScope::Extensions) {
        for (name, ext) in &cache.extensions {
            state.extensions.insert(
                name.clone(),
                NormalizedExtension {
                    owner: ext.owner.name.clone(),
                    schema: ext.schema.clone(),
                    version: ext.version.clone(),
                    relocatable: ext.relocatable,
                    members: ext
                        .members
                        .iter()
                        .map(|m| {
                            (
                                format!("{:?}", m.kind),
                                qualified_name(&m.id.schema, &m.id.name),
                            )
                        })
                        .collect(),
                    config_tables: ext
                        .config_tables
                        .iter()
                        .map(|c| qualified_name(&c.table.schema, &c.table.name))
                        .collect(),
                },
            );
        }
    }

    Ok(state)
}

pub(super) fn snapshot_simulator_state(
    state: &AnalysisState,
    schema_scope: &[String],
    scope: &[ComparisonScope],
) -> NormalizedState {
    let mut projection = NormalizedState::default();
    let known_function_ids = state
        .local
        .functions
        .iter()
        .filter_map(|(id, overlay)| {
            matches!(overlay, FunctionOverlay::Present(_)).then_some(id.clone())
        })
        .collect::<Vec<_>>();

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, overlay) in &state.local.schemas {
            let SchemaOverlay::Present(schema) = overlay else {
                continue;
            };
            // The state hydrator may retain an inferred namespace for an
            // out-of-scope relationship endpoint.  That evidence is needed
            // internally for dependency resolution, but the differential
            // projection must match the manifest's authoritative schema
            // scope, just like the live catalog snapshot does.
            if schema_scope.iter().any(|scoped| scoped == name) {
                projection
                    .schemas
                    .insert(name.clone(), schema.owner.name.clone());
            }
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for (member, overlay) in &state.local.roles {
            let safe_migrate::_internal::model::role::RoleOverlay::Present(role) = overlay else {
                continue;
            };
            for parent in &role.member_of {
                let grantor = state
                    .local
                    .role_membership_grantors
                    .iter()
                    .find(|provenance| provenance.member == *member && provenance.role == *parent)
                    .map(|provenance| provenance.grantor.name.clone());
                projection.roles.insert(NormalizedRoleMembership {
                    member: member.name.clone(),
                    role: parent.name.clone(),
                    admin: role.can_administer_membership.contains(parent),
                    inherit: role.can_inherit_from.contains(parent),
                    set: role.can_set_role_to.contains(parent),
                    grantor,
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Publications) {
        for (name, overlay) in &state.local.publications {
            let safe_migrate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            ) = overlay
            else {
                continue;
            };
            projection.publications.insert(
                name.clone(),
                NormalizedPublication {
                    owner: publication.owner.clone(),
                    scope: normalize_publication_scope(&publication.scope),
                    params: normalize_attributes(&publication.params),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, overlay) in &state.local.subscriptions {
            let safe_migrate::_internal::model::replication::SubscriptionOverlay::Present(
                subscription,
            ) = overlay
            else {
                continue;
            };
            projection
                .subscriptions
                .insert(name.clone(), normalize_subscription(subscription));
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (id, overlay) in &state.local.sequences {
            let SequenceOverlay::Present(sequence) = overlay else {
                continue;
            };
            projection.sequences.insert(
                qualified_name(&id.schema, &id.name),
                NormalizedSequence {
                    owner: sequence.owner.name.clone(),
                    owned_by: sequence.owned_by.as_ref().map(|(table, column)| {
                        format!("{}.{}", qualified_name(&table.schema, &table.name), column)
                    }),
                    kind: sequence.kind.clone(),
                    data_type: normalize_data_type(&sequence.parameters.data_type),
                    start_value: sequence.parameters.start_value,
                    increment: sequence.parameters.increment,
                    min_value: sequence.parameters.min_value,
                    max_value: sequence.parameters.max_value,
                    cache_size: sequence.parameters.cache_size,
                    cycle: sequence.parameters.cycle,
                    persistence: normalize_sequence_persistence(sequence.parameters.persistence),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for policy in &relation.policies {
                projection.policies.insert(NormalizedPolicy {
                    table: qualified_name(&id.schema, &id.name),
                    policy: policy.clone(),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (id, overlay) in &state.local.functions {
            let FunctionOverlay::Present(function) = overlay else {
                continue;
            };
            projection.functions.insert(
                qualified_name(&id.schema, &id.name),
                normalize_volatility(&function.volatility),
            );
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (id, overlay) in &state.local.types {
            let TypeOverlay::Present(type_state) = overlay else {
                continue;
            };
            projection.types.insert(
                qualified_name(&id.schema, &id.name),
                normalize_type_kind(&type_state.kind),
            );
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for (grantee, privileges) in &relation.privileges.grants {
                for privilege in privileges {
                    projection.privileges.insert(NormalizedPrivilege {
                        table: qualified_name(&id.schema, &id.name),
                        grantee: grantee.name.clone(),
                        privilege: normalize_privilege(*privilege),
                        grantable: relation.privileges.has_grant_option(grantee, *privilege),
                    });
                }
            }
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in state.local.constraints.values() {
            if constraint.kind == ConstraintKind::NotNull {
                continue;
            }
            projection.constraints.insert(NormalizedConstraint {
                table: qualified_name(&constraint.table_id.schema, &constraint.table_id.name),
                name: constraint.name.clone(),
                kind: normalize_constraint_kind(constraint.kind),
                validated: constraint.validated,
                definition: normalize_constraint_definition(constraint.definition.as_deref()),
                backing_index: constraint
                    .backing_index
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for edge in state.local.graph.edges() {
            let DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
                ..
            } = &edge.kind
            else {
                continue;
            };
            let Some(TriggerOverlay::Present(trigger)) = state.local.triggers.get(trigger_id)
            else {
                continue;
            };
            projection.triggers.insert(
                (
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    trigger.name.clone(),
                ),
                NormalizedTrigger {
                    function: qualified_name(&function_id.schema, &function_id.name),
                    enabled_mode: normalize_trigger_mode(trigger.enabled_mode),
                    row_level: trigger.row_level,
                    parent_trigger: trigger
                        .parent_trigger_id
                        .as_ref()
                        .map(|id| qualified_name(&id.schema, &id.name)),
                },
            );
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Columns) {
        for (id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            let mut normalized = NormalizedRelation {
                kind: normalize_relation_kind(relation.kind.clone()),
                owner: relation.owner.name.clone(),
                partition_strategy: relation.partition_type.clone(),
                partition_is_default: relation
                    .partition_bound
                    .as_deref()
                    .map(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT")),
                partition_bound: relation.partition_bound.clone(),
                partition_constraint: normalize_partition_constraint(
                    relation.partition_constraint.as_deref(),
                ),
                persistence: normalize_relation_persistence(relation.persistence.clone()),
                tablespace: relation.tablespace.clone(),
                access_method: normalize_access_method(
                    &relation.kind,
                    relation.access_method.as_deref(),
                ),
                cluster_index: relation.cluster_index.clone(),
                row_security: normalize_table_flag(&relation.kind, relation.row_security),
                force_row_security: normalize_table_flag(
                    &relation.kind,
                    relation.force_row_security,
                ),
                replica_identity: normalize_replica_identity(
                    &relation.kind,
                    relation.replica_identity.as_deref(),
                ),
                table_options: relation.table_options.clone(),
                of_type: relation
                    .of_type
                    .as_ref()
                    .map(|id| qualified_name(&id.schema, &id.name)),
                rules: relation
                    .rules
                    .iter()
                    .map(|(name, mode)| (name.clone(), format!("{mode:?}")))
                    .collect(),
                columns: BTreeMap::new(),
            };
            if scope.contains(&ComparisonScope::Columns) {
                for column in &relation.columns {
                    let data_type = normalize_data_type_with_identity(
                        &column
                            .data_type
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        column.type_id.as_ref(),
                    );
                    normalized.columns.insert(
                        column.name.clone(),
                        NormalizedColumn {
                            data_type: data_type.clone(),
                            is_nullable: column.is_nullable,
                            has_default: !relation.identity_columns.contains_key(&column.name)
                                && (column.default.is_some() || column.default_expr_text.is_some()),
                            generated: column.generated,
                            generation: normalize_generated_column(
                                relation.generated_columns.get(&column.name),
                                &known_function_ids,
                                &state.search_path_names(),
                            ),
                            identity_generation: relation
                                .identity_columns
                                .get(&column.name)
                                .map(|generation| format!("{generation:?}")),
                            storage: normalize_column_storage(
                                state,
                                &data_type,
                                column.storage.as_deref(),
                            ),
                            compression: column.compression.clone(),
                            statistics_target: normalize_statistics_target(
                                column.statistics_target,
                            ),
                            options: column.options.clone(),
                        },
                    );
                }
            }
            projection
                .relations
                .insert(qualified_name(&id.schema, &id.name), normalized);
        }
    }

    for edge in state.local.graph.edges() {
        match &edge.kind {
            DependencyKind::IndexOnRelation {
                definition,
                is_immediate,
                ..
            } if scope.contains(&ComparisonScope::Indexes) => {
                projection.indexes.insert(NormalizedIndex {
                    index: qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    table: qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    using_method: definition
                        .method
                        .as_ref()
                        .map(|method| method.to_ascii_lowercase()),
                    key_columns: definition.key_column_names(),
                    included_columns: definition.included_column_names(),
                    has_expression_keys: definition.has_expression_keys(),
                    has_predicate: definition.has_predicate(),
                    is_unique: definition.unique,
                    nulls_not_distinct: definition.nulls_not_distinct,
                    is_immediate: *is_immediate,
                    is_valid: definition.valid,
                    is_ready: definition.ready,
                    is_live: definition.live,
                    has_default_sort_order: definition
                        .keys
                        .iter()
                        .all(|key| key.order == IndexOrder::Default),
                    has_default_opclasses: definition
                        .keys
                        .iter()
                        .all(|key| matches!(key.opclass, KeyOpclass::Default(_))),
                    has_default_collations: definition.keys.iter().all(|key| {
                        matches!(
                            key.collation,
                            KeyCollation::NotCollatable | KeyCollation::Derived
                        )
                    }),
                });
            }
            DependencyKind::ForeignKey {
                constraint_name, ..
            } if scope.contains(&ComparisonScope::ForeignKeys) => {
                projection.foreign_keys.insert(NormalizedForeignKey {
                    from_table: qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    to_table: qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    constraint_name: constraint_name
                        .clone()
                        .unwrap_or_else(|| "<unnamed>".to_string()),
                });
            }
            DependencyKind::PartitionOf
            | DependencyKind::PartitionDetachPending
            | DependencyKind::InheritanceOf
                if scope.contains(&ComparisonScope::Partitions) =>
            {
                projection.partition_edges.insert((
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    !matches!(edge.kind, DependencyKind::InheritanceOf),
                    matches!(edge.kind, DependencyKind::PartitionDetachPending),
                ));
            }
            DependencyKind::IndexPartitionOf
                if scope.contains(&ComparisonScope::IndexPartitions) =>
            {
                projection.index_attachment_edges.insert((
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                    qualified_name(&edge.dependent.schema, &edge.dependent.name),
                ));
            }
            DependencyKind::ViewDependency { .. }
                if scope.contains(&ComparisonScope::ViewDependencies) =>
            {
                projection.view_dependencies.insert((
                    qualified_name(&edge.dependent.schema, &edge.dependent.name),
                    qualified_name(&edge.referenced.schema, &edge.referenced.name),
                ));
            }
            _ => {}
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (table_id, overlay) in &state.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            for (stats_id, statistics) in &relation.extended_statistics {
                projection.extended_statistics.insert(
                    qualified_name(&stats_id.schema, &stats_id.name),
                    NormalizedExtendedStatistics {
                        table: qualified_name(&table_id.schema, &table_id.name),
                        kinds: statistics.kinds.clone(),
                        columns: statistics.columns.clone(),
                        expressions: statistics.expressions.clone(),
                        target: normalize_statistics_target(statistics.target),
                    },
                );
            }
        }
    }

    if scope.contains(&ComparisonScope::Extensions) {
        for (name, overlay) in &state.local.extensions {
            let safe_migrate::_internal::model::extension::ExtensionOverlay::Present(ext) = overlay
            else {
                continue;
            };
            projection.extensions.insert(
                name.clone(),
                NormalizedExtension {
                    owner: ext.owner.name.clone(),
                    schema: ext.schema.clone(),
                    version: ext.version.clone(),
                    relocatable: ext.relocatable,
                    members: ext
                        .members
                        .iter()
                        .map(|m| {
                            (
                                format!("{:?}", m.kind),
                                qualified_name(&m.id.schema, &m.id.name),
                            )
                        })
                        .collect(),
                    config_tables: ext
                        .config_tables
                        .iter()
                        .map(|c| qualified_name(&c.table.schema, &c.table.name))
                        .collect(),
                },
            );
        }
    }

    projection
}

pub(super) fn compare_states(
    rule_dir: &str,
    fixture: &str,
    scope: &[ComparisonScope],
    live: &NormalizedState,
    simulator: &NormalizedState,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();

    if scope.contains(&ComparisonScope::Publications) {
        for (name, live_publication) in &live.publications {
            let Some(simulator_publication) = simulator.publications.get(name) else {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingPublicationInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept publication '{name}'"),
                });
                continue;
            };
            if live_publication != simulator_publication {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::PublicationDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "publication '{name}' differs: live={live_publication:?}, simulator={simulator_publication:?}"
                    ),
                });
            }
        }
        for name in simulator.publications.keys() {
            if !live.publications.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraPublicationInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept publication '{name}'"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Subscriptions) {
        for (name, live_subscription) in &live.subscriptions {
            let Some(simulator_subscription) = simulator.subscriptions.get(name) else {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSubscriptionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept subscription '{name}'"),
                });
                continue;
            };
            if live_subscription != simulator_subscription {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::SubscriptionDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "subscription '{name}' differs (connection metadata intentionally excluded): live={live_subscription:?}, simulator={simulator_subscription:?}"
                    ),
                });
            }
        }
        for name in simulator.subscriptions.keys() {
            if !live.subscriptions.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSubscriptionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept subscription '{name}'"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Roles) {
        for membership in live.roles.difference(&simulator.roles) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept role membership {} -> {} with ADMIN={}, INHERIT={}, SET={}, grantor={:?}",
                    membership.member,
                    membership.role,
                    membership.admin,
                    membership.inherit,
                    membership.set,
                    membership.grantor
                ),
            });
        }
        for membership in simulator.roles.difference(&live.roles) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::RoleMembershipMismatch,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept role membership {} -> {} with ADMIN={}, INHERIT={}, SET={}, grantor={:?}",
                    membership.member,
                    membership.role,
                    membership.admin,
                    membership.inherit,
                    membership.set,
                    membership.grantor
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Schemas) {
        for (name, live_owner) in &live.schemas {
            match simulator.schemas.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSchemaInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept schema {name}, but simulator removed it"),
                }),
                Some(simulator_owner) if simulator_owner != live_owner => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::SchemaOwnerMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "schema {name} owner mismatch: live={live_owner}, simulator={simulator_owner}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.schemas.keys() {
            if !live.schemas.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSchemaInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept schema {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Sequences) {
        for (name, live_sequence) in &live.sequences {
            match simulator.sequences.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingSequenceInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept sequence {name}, but simulator removed it"),
                }),
                Some(simulator_sequence) if simulator_sequence != live_sequence => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::SequenceDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "sequence {name} mismatch: live={live_sequence:?}, simulator={simulator_sequence:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.sequences.keys() {
            if !live.sequences.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraSequenceInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept sequence {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Relations) || scope.contains(&ComparisonScope::Partitions) {
        for (name, live_relation) in &live.relations {
            let Some(sim_relation) = simulator.relations.get(name) else {
                continue;
            };
            if sim_relation.partition_is_default != live_relation.partition_is_default
                || sim_relation.partition_bound != live_relation.partition_bound
                || normalize_constraint_definition(sim_relation.partition_constraint.as_deref())
                    != normalize_constraint_definition(
                        live_relation.partition_constraint.as_deref(),
                    )
            {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::RelationDefinitionMismatch,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("partition metadata mismatch for {name}: live={live_relation:?}, simulator={sim_relation:?}"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Relations) {
        for (name, live_relation) in &live.relations {
            match simulator.relations.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingObjectInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept relation {name}, but simulator removed it"),
                }),
                Some(sim_relation) if sim_relation.kind != live_relation.kind => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationKindMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation kind mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.kind, sim_relation.kind
                        ),
                    });
                }
                Some(sim_relation) if sim_relation.owner != live_relation.owner => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationOwnerMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation owner mismatch for {name}: live={}, simulator={}",
                            live_relation.owner, sim_relation.owner
                        ),
                    });
                }
                Some(sim_relation)
                    if sim_relation.partition_strategy != live_relation.partition_strategy =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::PartitionStrategyMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "partition strategy mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.partition_strategy, sim_relation.partition_strategy
                        ),
                    });
                }
                Some(sim_relation)
                    if sim_relation.persistence != live_relation.persistence
                        || sim_relation.tablespace != live_relation.tablespace
                        || sim_relation.access_method != live_relation.access_method
                        || sim_relation.cluster_index != live_relation.cluster_index
                        || sim_relation.row_security != live_relation.row_security
                        || sim_relation.force_row_security != live_relation.force_row_security
                        || sim_relation.replica_identity != live_relation.replica_identity
                        || sim_relation.table_options != live_relation.table_options
                        || sim_relation.of_type != live_relation.of_type
                        || sim_relation.rules != live_relation.rules =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::RelationDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "relation metadata mismatch for {name}: live={live_relation:?}, simulator={sim_relation:?}"
                        ),
                    });
                }
                Some(sim_relation)
                    if scope.contains(&ComparisonScope::Columns)
                        && sim_relation.columns != live_relation.columns =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::ColumnMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "column projection mismatch for {name}: live={:?}, simulator={:?}",
                            live_relation.columns, sim_relation.columns
                        ),
                    });
                }
                Some(_) => {}
            }
        }

        for name in simulator.relations.keys() {
            if !live.relations.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraObjectInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept relation {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Indexes) {
        for index in live.indexes.difference(&simulator.indexes) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingIndexInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("live PostgreSQL kept index {index:?}"),
            });
        }
        for index in simulator.indexes.difference(&live.indexes) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraIndexInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept index {index:?}"),
            });
        }
    }

    if scope.contains(&ComparisonScope::ForeignKeys) {
        for fk in live.foreign_keys.difference(&simulator.foreign_keys) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingForeignKeyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept FK {} ({} -> {})",
                    fk.constraint_name, fk.from_table, fk.to_table
                ),
            });
        }
        for fk in simulator.foreign_keys.difference(&live.foreign_keys) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraForeignKeyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept FK {} ({} -> {})",
                    fk.constraint_name, fk.from_table, fk.to_table
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Constraints) {
        for constraint in live.constraints.difference(&simulator.constraints) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingConstraintInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("live PostgreSQL kept constraint {constraint:?}"),
            });
        }
        for constraint in simulator.constraints.difference(&live.constraints) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraConstraintInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept constraint {constraint:?}"),
            });
        }
    }

    if scope.contains(&ComparisonScope::Functions) {
        for (name, live_volatility) in &live.functions {
            match simulator.functions.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingFunctionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept function {name}, but simulator removed it"),
                }),
                Some(simulator_volatility) if simulator_volatility != live_volatility => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::FunctionVolatilityMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "function {name} volatility mismatch: live={live_volatility}, simulator={simulator_volatility}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.functions.keys() {
            if !live.functions.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraFunctionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept function {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Types) {
        for (name, live_type) in &live.types {
            match simulator.types.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingTypeInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("live PostgreSQL kept type {name}, but simulator removed it"),
                }),
                Some(simulator_type) if simulator_type != live_type => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TypeDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "type {name} definition mismatch: live={live_type:?}, simulator={simulator_type:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.types.keys() {
            if !live.types.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraTypeInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!("simulator kept type {name}, but live PostgreSQL removed it"),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Privileges) {
        for privilege in live.privileges.difference(&simulator.privileges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPrivilegeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept {} on {} for {} (grantable={})",
                    privilege.privilege, privilege.table, privilege.grantee, privilege.grantable
                ),
            });
        }
        for privilege in simulator.privileges.difference(&live.privileges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPrivilegeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept {} on {} for {} (grantable={})",
                    privilege.privilege, privilege.table, privilege.grantee, privilege.grantable
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Policies) {
        for policy in live.policies.difference(&simulator.policies) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPolicyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept policy {} on {}",
                    policy.policy, policy.table
                ),
            });
        }
        for policy in simulator.policies.difference(&live.policies) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPolicyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "simulator kept policy {} on {}",
                    policy.policy, policy.table
                ),
            });
        }
    }

    if scope.contains(&ComparisonScope::Triggers) {
        for (key, live_trigger) in &live.triggers {
            match simulator.triggers.get(key) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingTriggerInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "live PostgreSQL kept trigger {} on {}, but simulator removed it",
                        key.1, key.0
                    ),
                }),
                Some(simulator_trigger) if simulator_trigger.function != live_trigger.function => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerFunctionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} function mismatch: live={}, simulator={}",
                            key.1, key.0, live_trigger.function, simulator_trigger.function
                        ),
                    });
                }
                Some(simulator_trigger)
                    if simulator_trigger.enabled_mode != live_trigger.enabled_mode =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerEnableModeMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} enabled-mode mismatch: live={}, simulator={}",
                            key.1, key.0, live_trigger.enabled_mode, simulator_trigger.enabled_mode
                        ),
                    });
                }
                Some(simulator_trigger)
                    if simulator_trigger.row_level != live_trigger.row_level
                        || simulator_trigger.parent_trigger != live_trigger.parent_trigger =>
                {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::TriggerDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "trigger {} on {} definition mismatch: live={live_trigger:?}, simulator={simulator_trigger:?}",
                            key.1, key.0
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for key in simulator.triggers.keys() {
            if !live.triggers.contains_key(key) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraTriggerInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "simulator kept trigger {} on {}, but live PostgreSQL removed it",
                        key.1, key.0
                    ),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::ExtendedStatistics) {
        for (name, live_statistics) in &live.extended_statistics {
            match simulator.extended_statistics.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingExtendedStatisticsInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "live PostgreSQL kept extended statistics {name} on {}",
                        live_statistics.table
                    ),
                }),
                Some(simulator_statistics) if simulator_statistics != live_statistics => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::ExtendedStatisticsDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "extended statistics {name} mismatch: live={live_statistics:?}, simulator={simulator_statistics:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.extended_statistics.keys() {
            if !live.extended_statistics.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraExtendedStatisticsInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "simulator kept extended statistics {name}, but live PostgreSQL removed it"
                    ),
                });
            }
        }
    }

    if scope.contains(&ComparisonScope::Partitions) {
        for edge in live.partition_edges.difference(&simulator.partition_edges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingPartitionEdgeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept partition edge {} -> {}",
                    edge.0, edge.1
                ),
            });
        }
        for edge in simulator.partition_edges.difference(&live.partition_edges) {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraPartitionEdgeInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept partition edge {} -> {}", edge.0, edge.1),
            });
        }
    }

    if scope.contains(&ComparisonScope::IndexPartitions) {
        for (parent, child) in live
            .index_attachment_edges
            .difference(&simulator.index_attachment_edges)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingIndexAttachmentInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("live PostgreSQL attached index {child} to {parent}"),
            });
        }
        for (parent, child) in simulator
            .index_attachment_edges
            .difference(&live.index_attachment_edges)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraIndexAttachmentInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator attached index {child} to {parent}"),
            });
        }
    }

    if scope.contains(&ComparisonScope::ViewDependencies) {
        for edge in live
            .view_dependencies
            .difference(&simulator.view_dependencies)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::MissingViewDependencyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!(
                    "live PostgreSQL kept view dependency {} -> {}",
                    edge.0, edge.1
                ),
            });
        }
        for edge in simulator
            .view_dependencies
            .difference(&live.view_dependencies)
        {
            mismatches.push(Mismatch {
                rule_dir: rule_dir.to_string(),
                fixture: fixture.to_string(),
                category: MismatchCategory::ExtraViewDependencyInSimulator,
                root_cause: RootCauseClassification::SimulatorBug,
                note: format!("simulator kept view dependency {} -> {}", edge.0, edge.1),
            });
        }
    }

    if scope.contains(&ComparisonScope::Extensions) {
        for (name, live_ext) in &live.extensions {
            match simulator.extensions.get(name) {
                None => mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::MissingExtensionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "live PostgreSQL kept extension {name}, but simulator removed it"
                    ),
                }),
                Some(simulator_ext) if simulator_ext != live_ext => {
                    mismatches.push(Mismatch {
                        rule_dir: rule_dir.to_string(),
                        fixture: fixture.to_string(),
                        category: MismatchCategory::ExtensionDefinitionMismatch,
                        root_cause: RootCauseClassification::SimulatorBug,
                        note: format!(
                            "extension {name} definition mismatch: live={live_ext:?}, simulator={simulator_ext:?}"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
        for name in simulator.extensions.keys() {
            if !live.extensions.contains_key(name) {
                mismatches.push(Mismatch {
                    rule_dir: rule_dir.to_string(),
                    fixture: fixture.to_string(),
                    category: MismatchCategory::ExtraExtensionInSimulator,
                    root_cause: RootCauseClassification::SimulatorBug,
                    note: format!(
                        "simulator kept extension {name}, but live PostgreSQL removed it"
                    ),
                });
            }
        }
    }

    mismatches
}
