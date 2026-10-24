use super::*;

pub(super) fn load_routines(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
    builtin_types: &BuiltinTypeCatalogue,
) -> Result<std::collections::HashMap<ObjectId, crate::_internal::model::function::FunctionState>> {
    let query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            p.proname AS func_name,
            ARRAY(
                SELECT pg_catalog.format_type(t, NULL)
                FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS u(t, n)
                ORDER BY n
            )::text[] AS arg_types,
            ARRAY(
                SELECT pg_catalog.format_type(t, NULL)
                FROM unnest(
                    COALESCE(p.proallargtypes, p.proargtypes)::oid[]
                ) WITH ORDINALITY AS u(t, n)
                ORDER BY n
            )::text[] AS all_arg_types,
            -- PostgreSQL spells an unnamed parameter as an empty name and
            -- leaves `proargmodes` NULL when every parameter is an input.
            COALESCE(p.proargnames::text[], ARRAY[]::text[]) AS param_names,
            COALESCE(p.proargmodes::text[], ARRAY[]::text[]) AS param_modes,
            p.pronargdefaults::int4 AS default_count,
            p.proretset AS returns_set,
            pg_catalog.pg_get_function_result(p.oid) AS return_type,
            p.provolatile::text AS volatility,
            p.prokind::text AS routine_kind,
            g.aggkind::text AS aggregate_kind,
            CASE
                WHEN g.aggkind = 'n' THEN p.pronargs::int4
                ELSE g.aggnumdirectargs::int4
            END AS aggregate_direct_count,
            l.lanname AS language,
            p.prosecdef AS security_definer,
            owner_ns.nspname AS internal_owner_schema,
            owner_t.typname AS internal_owner_name
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        LEFT JOIN pg_aggregate g ON g.aggfnoid = p.oid
        LEFT JOIN LATERAL (
            SELECT d.refobjid AS owner_oid
            FROM pg_depend d
            WHERE d.classid = 'pg_proc'::regclass
              AND d.objid = p.oid
              AND d.refclassid = 'pg_type'::regclass
              AND d.deptype = 'i'
            LIMIT 1
        ) owner ON TRUE
        LEFT JOIN pg_type owner_t ON owner_t.oid = owner.owner_oid
        LEFT JOIN pg_namespace owner_ns ON owner_ns.oid = owner_t.typnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prokind IN ('f', 'p', 'a', 'w')
          {schema_filter};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load routines from pg_proc")?
        .into_iter()
        .map(|row| {
            let schema_name: String = row.try_get("schema_name").context("routine schema")?;
            let function_name: String = row.try_get("func_name").context("routine name")?;
            let raw_arg_types: Vec<String> =
                row.try_get("arg_types").context("routine argument types")?;
            let volatility_code: String =
                row.try_get("volatility").context("routine volatility")?;
            let volatility = routine_volatility_from_pg(&volatility_code)?;
            let routine_kind_code: String = row.try_get("routine_kind").context("routine kind")?;
            let routine_kind = routine_kind_from_pg(&routine_kind_code)?;
            let arg_types = raw_arg_types
                .iter()
                .map(|arg_type| {
                    crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
                        arg_type,
                        builtin_types,
                    )
                    .render()
                })
                .collect::<Vec<_>>();
            let id = ObjectId::new(
                schema_name,
                format!("{}({})", function_name, arg_types.join(",")),
            );
            let security_definer: bool = row
                .try_get("security_definer")
                .context("routine security mode")?;
            let all_arg_types = row
                .try_get::<_, Option<Vec<String>>>("all_arg_types")
                .context("routine argument types")?
                .unwrap_or_else(|| raw_arg_types.clone());
            let param_names = row
                .try_get::<_, Vec<String>>("param_names")
                .context("routine parameter names")?;
            let param_modes = row
                .try_get::<_, Vec<String>>("param_modes")
                .context("routine parameter modes")?;
            let parameters = all_arg_types
                .iter()
                .enumerate()
                .map(|(position, ty)| {
                    let mode = match param_modes.get(position) {
                        // An absent `proargmodes` array means every parameter is
                        // an input, which is how PostgreSQL reads it.
                        None => crate::_internal::model::function::ParameterMode::In,
                        Some(code) => crate::_internal::model::function::ParameterMode::from_pg(code)
                            .ok_or_else(|| anyhow::anyhow!("unknown routine parameter mode {code}"))?,
                    };
                    Ok(crate::_internal::model::function::RoutineParameter {
                        name: param_names
                            .get(position)
                            .filter(|name| !name.is_empty())
                            .cloned(),
                        mode,
                        ty: crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
                            ty, builtin_types,
                        )
                        .render(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            debug_assert_eq!(
                parameters
                    .iter()
                    .filter(|parameter| parameter.mode.is_input())
                    .map(|parameter| parameter.ty.clone())
                    .collect::<Vec<_>>(),
                arg_types,
                "the input signature must be the parameter list restricted to inputs"
            );
            let aggregate = match routine_kind {
                crate::_internal::model::function::RoutineKind::Aggregate => {
                    let kind_code = row
                        .try_get::<_, Option<String>>("aggregate_kind")
                        .context("aggregate kind")?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "aggregate {id} has no pg_aggregate row; catalog is inconsistent"
                            )
                        })?;
                    let kind = crate::_internal::model::aggregate::AggregateKind::from_catalog(
                        &kind_code,
                    )
                    .ok_or_else(|| anyhow::anyhow!("unknown aggregate kind {kind_code}"))?;
                    let direct_count = row
                        .try_get::<_, Option<i32>>("aggregate_direct_count")
                        .context("aggregate direct argument count")?
                        .ok_or_else(|| anyhow::anyhow!("aggregate {id} has no direct argument count"))?;
                    Some(crate::_internal::model::aggregate::AggregateMetadata::new(
                        kind,
                        direct_count.max(0) as usize,
                    ))
                }
                _ => None,
            };
            Ok((
                id.clone(),
                crate::_internal::model::function::FunctionState {
                    id,
                    routine_kind,
                    arg_types,
                    arg_type_ids: Vec::new(),
                    // `pg_get_function_result` renders a set-returning routine
                    // as `SETOF t`; `proretset` carries the flag, so the type
                    // is stored alone and the two compare independently.
                    return_type: {
                        let rendered = row
                            .try_get::<_, Option<String>>("return_type")
                            .context("routine return type")?
                            .unwrap_or_default();
                        match rendered.strip_prefix("SETOF ") {
                            Some(base) => base.to_string(),
                            None => rendered,
                        }
                    },
                    return_type_id: None,
                    returns_set: row
                        .try_get("returns_set")
                        .context("routine SETOF flag")?,
                    parameters,
                    default_count: row
                        .try_get::<_, i32>("default_count")
                        .context("routine parameter default count")?
                        .max(0) as u32,
                    volatility,
                    language: row.try_get("language").context("routine language")?,
                    security: if security_definer {
                        crate::_internal::model::function::SecurityMode::Definer
                    } else {
                        crate::_internal::model::function::SecurityMode::Invoker
                    },
                    internal_type_owner: match (
                        row.try_get::<_, Option<String>>("internal_owner_schema")
                            .context("internal owner schema")?,
                        row.try_get::<_, Option<String>>("internal_owner_name")
                            .context("internal owner name")?,
                    ) {
                        (Some(schema), Some(name)) => Some(ObjectId::new(schema, name)),
                        _ => None,
                    },
                    aggregate,
                },
            ))
        })
        .collect()
}
