use super::*;

pub(super) fn load_view_object_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    builtin_types: &BuiltinTypeCatalogue,
) -> Result<Vec<crate::_internal::db::cache::ViewObjectDependencyCache>> {
    let query = r#"
        SELECT vn.nspname AS obj_schema,
               vc.relname AS obj_name,
               'pg_proc'::text AS ref_kind,
               pn.nspname AS ref_schema,
               p.proname AS ref_name,
               ARRAY(
                   SELECT pg_catalog.format_type(t, NULL)
                   FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS u(t, n)
                   ORDER BY n
               )::text[] AS ref_args
        FROM pg_rewrite rw
        JOIN pg_class vc ON vc.oid = rw.ev_class
        JOIN pg_namespace vn ON vn.oid = vc.relnamespace
        JOIN pg_depend d ON d.objid = rw.oid
        JOIN pg_proc p ON p.oid = d.refobjid
        JOIN pg_namespace pn ON pn.oid = p.pronamespace
            WHERE vc.relkind IN ('v', 'm')
              AND d.classid = 'pg_rewrite'::regclass
              AND d.refclassid = 'pg_proc'::regclass
              AND d.deptype = 'n'
              AND vn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND vn.nspname <> 'information_schema'
              AND pn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND pn.nspname <> 'information_schema'
              AND (
              $1::text[] IS NULL
              OR vn.nspname = ANY($1)
              OR pn.nspname = ANY($1)
          )
        UNION ALL
        SELECT vn.nspname AS obj_schema,
               vc.relname AS obj_name,
               'pg_type'::text AS ref_kind,
               tn.nspname AS ref_schema,
               t.typname AS ref_name,
               NULL::text[] AS ref_args
        FROM pg_rewrite rw
        JOIN pg_class vc ON vc.oid = rw.ev_class
        JOIN pg_namespace vn ON vn.oid = vc.relnamespace
        JOIN pg_depend d ON d.objid = rw.oid
        JOIN pg_type t ON t.oid = d.refobjid
        JOIN pg_namespace tn ON tn.oid = t.typnamespace
            WHERE vc.relkind IN ('v', 'm')
              AND d.classid = 'pg_rewrite'::regclass
              AND d.refclassid = 'pg_type'::regclass
              AND d.deptype = 'n'
              AND vn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND vn.nspname <> 'information_schema'
              AND tn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND tn.nspname <> 'information_schema'
              AND (
              $1::text[] IS NULL
              OR vn.nspname = ANY($1)
              OR tn.nspname = ANY($1)
          )
    "#;

    let rows = client
        .query(query, &[schema_values])
        .context("Failed to load view object dependencies from pg_rewrite/pg_depend")?;

    let mut dependencies: Vec<crate::_internal::db::cache::ViewObjectDependencyCache> = Vec::new();
    for row in rows {
        let dependent = ObjectId::new(
            row.try_get::<_, String>("obj_schema")
                .context("view schema")?,
            row.try_get::<_, String>("obj_name").context("view name")?,
        );
        let schema = row
            .try_get::<_, String>("ref_schema")
            .context("referenced schema")?;
        let name = row
            .try_get::<_, String>("ref_name")
            .context("referenced name")?;
        let kind: String = row.try_get("ref_kind").context("referenced kind")?;
        let raw_args: Vec<String> = row
            .try_get::<_, Option<Vec<String>>>("ref_args")
            .context("referenced argument types")?
            .unwrap_or_default();
        let target = match kind.as_str() {
            "pg_proc" => {
                let signature = raw_args
                    .iter()
                    .map(|argument| {
                        crate::_internal::analysis::resolver::Resolver::normalize_function_arg_type(
                            argument,
                            builtin_types,
                        )
                        .render()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                ViewDependencyTarget::Routine {
                    routine: ObjectId::new(schema, format!("{name}({signature})")),
                }
            }
            _ => ViewDependencyTarget::Type {
                ty: ObjectId::new(schema, name),
            },
        };
        let dependency =
            crate::_internal::db::cache::ViewObjectDependencyCache { dependent, target };
        if !dependencies.contains(&dependency) {
            dependencies.push(dependency);
        }
    }
    Ok(dependencies)
}

pub(super) fn load_view_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<Vec<ViewDependencyCache>> {
    let query = r#"
        SELECT DISTINCT
            vn.nspname AS obj_schema,
            vc.relname AS obj_name,
            tn.nspname AS ref_schema,
            tc.relname AS ref_name,
            a.attname AS ref_column
        FROM pg_rewrite rw
        JOIN pg_class vc ON vc.oid = rw.ev_class
        JOIN pg_namespace vn ON vn.oid = vc.relnamespace
        JOIN pg_depend d ON d.objid = rw.oid
        JOIN pg_class tc ON tc.oid = d.refobjid
        JOIN pg_namespace tn ON tn.oid = tc.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = tc.oid
         AND a.attnum = d.refobjsubid
         AND NOT a.attisdropped
            WHERE vc.relkind IN ('v', 'm')
              AND d.classid = 'pg_rewrite'::regclass
              AND d.refclassid = 'pg_class'::regclass
              AND d.deptype = 'n'
              AND tc.oid <> vc.oid
              AND tc.relkind IN ('r', 'p', 'v', 'm')
              AND vn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND vn.nspname <> 'information_schema'
              AND tn.nspname NOT LIKE 'pg\_%' ESCAPE '\'
              AND tn.nspname <> 'information_schema'
              AND (
              $1::text[] IS NULL
              OR vn.nspname = ANY($1)
              OR tn.nspname = ANY($1)
          )
    "#;

    let rows = client
        .query(query, &[schema_values])
        .context("Failed to load view dependencies from pg_rewrite/pg_depend")?;
    rows.into_iter()
        .map(|row| {
            Ok(ViewDependencyCache {
                dependent: ObjectId::new(
                    row.try_get::<_, String>("obj_schema")
                        .context("view dependency schema")?,
                    row.try_get::<_, String>("obj_name")
                        .context("view dependency name")?,
                ),
                referenced: ObjectId::new(
                    row.try_get::<_, String>("ref_schema")
                        .context("view dependency referenced schema")?,
                    row.try_get::<_, String>("ref_name")
                        .context("view dependency referenced name")?,
                ),
                referenced_column: row
                    .try_get("ref_column")
                    .context("view dependency referenced column")?,
            })
        })
        .collect()
}

/// Every dependency crossing an explicit schema scope, with both endpoints.
///
/// One query resolves both sides of each `pg_depend` row: the in-scope object
/// being depended on, and the out-of-scope object that depends on it. Class to
/// catalog resolution lives in one lateral per side, so a dependent class
/// cannot be handled inconsistently between families.
pub(super) fn load_scoped_external_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<ScopedExternalDependencies> {
    let Some(schemas) = schema_values else {
        return Ok(ScopedExternalDependencies {
            edges: Vec::new(),
            external_schemas: Vec::new(),
        });
    };
    if schemas.is_empty() {
        return Ok(ScopedExternalDependencies {
            edges: Vec::new(),
            external_schemas: Vec::new(),
        });
    }
    let query = r#"
        SELECT DISTINCT
            ref_side.family AS ref_family,
            ref_side.relkind AS ref_relkind,
            ref_side.schema AS ref_schema,
            ref_side.name AS ref_name,
            dep_side.schema AS dep_schema,
            dep_side.name AS dep_name
        FROM pg_depend d
        CROSS JOIN LATERAL (
            SELECT 'r' AS family, c.relkind::text AS relkind,
                   n.nspname AS schema, c.relname AS name
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE d.refclassid = 'pg_class'::regclass AND c.oid = d.refobjid
            UNION ALL
            SELECT 't', NULL, n.nspname, t.typname
            FROM pg_type t
            JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE d.refclassid = 'pg_type'::regclass AND t.oid = d.refobjid
            UNION ALL
            SELECT 'p', NULL, n.nspname, p.proname
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE d.refclassid = 'pg_proc'::regclass AND p.oid = d.refobjid
            UNION ALL
            SELECT 'o', NULL, n.nspname, o.oprname
            FROM pg_operator o
            JOIN pg_namespace n ON n.oid = o.oprnamespace
            WHERE d.refclassid = 'pg_operator'::regclass AND o.oid = d.refobjid
        ) ref_side
        LEFT JOIN LATERAL (
            SELECT n.nspname AS schema, c.relname AS name
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.oid = COALESCE(
                CASE d.classid WHEN 'pg_class'::regclass THEN d.objid END,
                CASE d.classid
                    WHEN 'pg_constraint'::regclass
                        THEN (SELECT conrelid FROM pg_constraint WHERE oid = d.objid)
                    WHEN 'pg_rewrite'::regclass
                        THEN (SELECT ev_class FROM pg_rewrite WHERE oid = d.objid)
                    WHEN 'pg_attrdef'::regclass
                        THEN (SELECT adrelid FROM pg_attrdef WHERE oid = d.objid)
                    WHEN 'pg_trigger'::regclass
                        THEN (SELECT tgrelid FROM pg_trigger WHERE oid = d.objid)
                    WHEN 'pg_policy'::regclass
                        THEN (SELECT polrelid FROM pg_policy WHERE oid = d.objid)
                END
            )
            UNION ALL
            SELECT n.nspname, p.proname
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE d.classid = 'pg_proc'::regclass AND p.oid = d.objid
        ) dep_side ON TRUE
        WHERE ref_side.schema = ANY($1)
          AND (
            dep_side.schema IS NULL
            OR NOT (dep_side.schema = ANY($1))
          )
          AND (
            dep_side.schema IS NULL
            OR (
              dep_side.schema NOT LIKE 'pg\_%' ESCAPE '\'
              AND dep_side.schema <> 'information_schema'
            )
          )
    "#;
    let mut edges = Vec::new();
    let mut external_schemas: std::collections::BTreeSet<String> = Default::default();
    for row in client
        .query(query, &[schemas])
        .context("Failed to load scoped external dependency boundaries")?
    {
        let relkind: Option<String> = row.try_get("ref_relkind")?;
        let family = match (
            row.try_get::<_, String>("ref_family")?.as_str(),
            relkind.as_deref(),
        ) {
            ("r", Some("i" | "I")) => CatalogFamily::Indexes,
            ("r", _) => CatalogFamily::Relations,
            ("t", _) => CatalogFamily::Types,
            ("p", _) => CatalogFamily::Routines,
            // An operator is a real cross-scope reference, but nothing in the
            // model is an operator, so it has no family to belong to. It still
            // names a schema the consumer should know about.
            ("o", _) => {
                if let Some(schema) = row.try_get::<_, Option<String>>("dep_schema")? {
                    external_schemas.insert(schema);
                }
                continue;
            }
            (other, _) => return Err(anyhow::anyhow!("unknown dependency family {other}")),
        };
        let scoped = ObjectId::new(
            row.try_get::<_, String>("ref_schema")?,
            row.try_get::<_, String>("ref_name")?,
        );
        let external_schema: Option<String> = row.try_get("dep_schema")?;
        edges.push(match external_schema {
            Some(schema) => ScopedDependencyEdge::new(
                family,
                scoped,
                ObjectId::new(schema, row.try_get::<_, String>("dep_name")?),
            ),
            None => ScopedDependencyEdge::unresolved_external(family, scoped),
        });
    }
    Ok(ScopedExternalDependencies {
        edges,
        external_schemas: external_schemas.into_iter().collect(),
    })
}

/// What the scope-boundary query observed: family-attributed edges plus the
/// schemas that reference the scope through a class the model does not hold.
pub(super) struct ScopedExternalDependencies {
    pub(super) edges: Vec<ScopedDependencyEdge>,
    pub(super) external_schemas: Vec<String>,
}
