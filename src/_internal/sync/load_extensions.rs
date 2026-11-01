use super::*;

pub(super) fn load_extensions(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    builtin_types: &BuiltinTypeCatalogue,
) -> Result<std::collections::HashMap<String, crate::_internal::model::extension::ExtensionState>> {
    let scope = schema_values.as_ref().map(|schemas| {
        schemas
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>()
    });
    let mut extensions = client
        .query(
            "
            SELECT
                e.extname AS extension_name,
                e.extversion AS extension_version,
                n.nspname AS extension_schema,
                e.extrelocatable AS relocatable,
                pg_catalog.pg_get_userbyid(e.extowner) AS owner_name
            FROM pg_extension e
            LEFT JOIN pg_namespace n ON n.oid = e.extnamespace
            ORDER BY e.extname;
            ",
            &[],
        )
        .context("Failed to load extensions from pg_extension")?
        .into_iter()
        .map(|row| {
            let name: String = row.try_get("extension_name").context("extension name")?;
            Ok((
                name.clone(),
                crate::_internal::model::extension::ExtensionState {
                    name,
                    schema: row
                        .try_get("extension_schema")
                        .context("extension schema")?,
                    version: row
                        .try_get("extension_version")
                        .context("extension version")?,
                    relocatable: row
                        .try_get("relocatable")
                        .context("extension relocatable")?,
                    owner: relation_owner_id(
                        row.try_get::<_, String>("owner_name")
                            .context("extension owner")?,
                    ),
                    members: Default::default(),
                    members_complete: true,
                    config_tables: Vec::new(),
                    generation: 0,
                },
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()?;

    let member_rows = client
        .query(
            "
            SELECT
                e.extname AS extension_name,
                d.classid::regclass::text AS class_name,
                d.objid AS object_id,
                d.objsubid AS object_subid,
                n.nspname AS namespace_name,
                cn.nspname AS relation_schema,
                c.relname AS relation_name,
                c.relkind::text AS relation_kind,
                tn.nspname AS type_schema,
                t.typname AS type_name,
                pn.nspname AS routine_schema,
                p.proname AS routine_name,
                ARRAY(
                    SELECT pg_catalog.format_type(t, NULL)
                    FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS u(t, n)
                    ORDER BY n
                )::text[] AS routine_arg_types,
                conn.nspname AS constraint_schema,
                conrel.relname AS constraint_table,
                con.conname AS constraint_name,
                tgn.nspname AS trigger_schema,
                tgrel.relname AS trigger_table,
                tg.tgname AS trigger_name,
                coln.nspname AS collation_schema,
                col.collname AS collation_name,
                pg_catalog.format_type(castsrc.oid, NULL) AS cast_source,
                pg_catalog.format_type(casttgt.oid, NULL) AS cast_target
            FROM pg_extension e
            JOIN pg_depend d
              ON d.refclassid = 'pg_extension'::regclass
             AND d.refobjid = e.oid
             AND d.deptype = 'e'
            LEFT JOIN pg_namespace n
              ON d.classid = 'pg_namespace'::regclass AND n.oid = d.objid
            LEFT JOIN pg_class c
              ON d.classid = 'pg_class'::regclass AND c.oid = d.objid
            LEFT JOIN pg_namespace cn ON cn.oid = c.relnamespace
            LEFT JOIN pg_type t
              ON d.classid = 'pg_type'::regclass AND t.oid = d.objid
            LEFT JOIN pg_namespace tn ON tn.oid = t.typnamespace
            LEFT JOIN pg_proc p
              ON d.classid = 'pg_proc'::regclass AND p.oid = d.objid
            LEFT JOIN pg_namespace pn ON pn.oid = p.pronamespace
            LEFT JOIN pg_constraint con
              ON d.classid = 'pg_constraint'::regclass AND con.oid = d.objid
            LEFT JOIN pg_class conrel ON conrel.oid = con.conrelid
            LEFT JOIN pg_namespace conn ON conn.oid = conrel.relnamespace
            LEFT JOIN pg_trigger tg
              ON d.classid = 'pg_trigger'::regclass AND tg.oid = d.objid
            LEFT JOIN pg_class tgrel ON tgrel.oid = tg.tgrelid
            LEFT JOIN pg_namespace tgn ON tgn.oid = tgrel.relnamespace
            LEFT JOIN pg_collation col
              ON d.classid = 'pg_collation'::regclass AND col.oid = d.objid
            LEFT JOIN pg_namespace coln ON coln.oid = col.collnamespace
            LEFT JOIN pg_cast cast_row
              ON d.classid = 'pg_cast'::regclass AND cast_row.oid = d.objid
            LEFT JOIN pg_type castsrc ON castsrc.oid = cast_row.castsource
            LEFT JOIN pg_type casttgt ON casttgt.oid = cast_row.casttarget
            ORDER BY e.extname, d.classid, d.objid;
            ",
            &[],
        )
        .context("Failed to load extension members from pg_depend")?;

    for row in member_rows {
        let extension_name: String = row
            .try_get("extension_name")
            .context("extension member extension name")?;
        let Some(extension) = extensions.get_mut(&extension_name) else {
            continue;
        };
        let class_name: String = row
            .try_get("class_name")
            .context("extension member class")?;
        let object_id: u32 = row
            .try_get("object_id")
            .context("extension member object")?;
        let object_subid: i32 = row
            .try_get("object_subid")
            .context("extension member subobject")?;
        let (kind, id, schema) = match class_name.as_str() {
            "pg_namespace" => {
                let name: String = row
                    .try_get("namespace_name")
                    .context("extension member schema name")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Schema,
                    ObjectId::new("", name.clone()),
                    Some(name),
                )
            }
            "pg_class" => {
                let schema: String = row
                    .try_get("relation_schema")
                    .context("extension member relation schema")?;
                let name: String = row
                    .try_get("relation_name")
                    .context("extension member relation name")?;
                let relkind: String = row
                    .try_get("relation_kind")
                    .context("extension member relation kind")?;
                let kind = match relkind.as_str() {
                    "S" => crate::_internal::model::extension::ExtensionMemberKind::Sequence,
                    "i" | "I" => crate::_internal::model::extension::ExtensionMemberKind::Index,
                    _ => crate::_internal::model::extension::ExtensionMemberKind::Relation,
                };
                (kind, ObjectId::new(schema.clone(), name), Some(schema))
            }
            "pg_type" => {
                let schema: String = row
                    .try_get("type_schema")
                    .context("extension member type schema")?;
                let name: String = row
                    .try_get("type_name")
                    .context("extension member type name")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Type,
                    ObjectId::new(schema.clone(), name),
                    Some(schema),
                )
            }
            "pg_proc" => {
                let schema: String = row
                    .try_get("routine_schema")
                    .context("extension member routine schema")?;
                let name: String = row
                    .try_get("routine_name")
                    .context("extension member routine name")?;
                let raw_arg_types: Vec<String> = row
                    .try_get("routine_arg_types")
                    .context("extension member routine arguments")?;
                let signature = raw_arg_types
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
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Routine,
                    ObjectId::new(schema.clone(), format!("{name}({signature})")),
                    Some(schema),
                )
            }
            "pg_constraint" => {
                let schema: String = row
                    .try_get("constraint_schema")
                    .context("extension member constraint schema")?;
                let table: String = row
                    .try_get("constraint_table")
                    .context("extension member constraint table")?;
                let name: String = row
                    .try_get("constraint_name")
                    .context("extension member constraint name")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Constraint,
                    ObjectId::new(schema.clone(), format!("{table}.{name}")),
                    Some(schema),
                )
            }
            "pg_trigger" => {
                let schema: String = row
                    .try_get("trigger_schema")
                    .context("extension member trigger schema")?;
                let table: String = row
                    .try_get("trigger_table")
                    .context("extension member trigger table")?;
                let name: String = row
                    .try_get("trigger_name")
                    .context("extension member trigger name")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Trigger,
                    ObjectId::new(schema.clone(), format!("{table}.{name}")),
                    Some(schema),
                )
            }
            "pg_collation" => {
                let schema: String = row
                    .try_get("collation_schema")
                    .context("extension member collation schema")?;
                let name: String = row
                    .try_get("collation_name")
                    .context("extension member collation name")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Collation,
                    ObjectId::new(schema.clone(), name),
                    Some(schema),
                )
            }
            "pg_cast" => {
                let source: String = row
                    .try_get("cast_source")
                    .context("extension member cast source")?;
                let target: String = row
                    .try_get("cast_target")
                    .context("extension member cast target")?;
                (
                    crate::_internal::model::extension::ExtensionMemberKind::Cast,
                    ObjectId::new("", format!("{source}->{target}")),
                    None,
                )
            }
            _ => (
                crate::_internal::model::extension::ExtensionMemberKind::Unmodeled(
                    class_name.clone(),
                ),
                ObjectId::new(
                    "",
                    if object_subid == 0 {
                        object_id.to_string()
                    } else {
                        format!("{object_id}.{object_subid}")
                    },
                ),
                None,
            ),
        };
        if let Some(schema) = schema.as_deref() {
            if scope.as_ref().is_some_and(|scope| !scope.contains(schema)) {
                extension.members_complete = false;
            }
        } else if scope.is_some() {
            extension.members_complete = false;
        }
        if matches!(
            kind,
            crate::_internal::model::extension::ExtensionMemberKind::Unmodeled(_)
        ) {
            extension.members_complete = false;
        }
        extension
            .members
            .insert(crate::_internal::model::extension::ExtensionMember { kind, id });
    }

    for row in client
        .query(
            "
            SELECT
                e.extname AS extension_name,
                n.nspname AS table_schema,
                c.relname AS table_name,
                e.extcondition[cfg.ord] AS condition
            FROM pg_extension e
            JOIN LATERAL unnest(e.extconfig) WITH ORDINALITY AS cfg(relid, ord) ON TRUE
            JOIN pg_class c ON c.oid = cfg.relid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            ORDER BY e.extname, cfg.ord;
            ",
            &[],
        )
        .context("Failed to load extension configuration tables")?
    {
        let extension_name: String = row
            .try_get("extension_name")
            .context("extension configuration table extension")?;
        let Some(extension) = extensions.get_mut(&extension_name) else {
            continue;
        };
        extension
            .config_tables
            .push(crate::_internal::model::extension::ExtensionConfigTable {
                table: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("extension configuration table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("extension configuration table name")?,
                ),
                condition: row
                    .try_get("condition")
                    .context("extension configuration table condition")?,
            });
    }

    Ok(extensions)
}
