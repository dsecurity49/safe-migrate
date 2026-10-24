use super::*;

pub(super) fn load_casts(
    client: &mut impl GenericClient,
) -> Result<crate::_internal::model::cast::CastCatalogue> {
    let rows = client
        .query(
            "
            SELECT
                pg_catalog.format_type(c.castsource, NULL) AS source,
                pg_catalog.format_type(c.casttarget, NULL) AS target
            FROM pg_catalog.pg_cast c
            JOIN pg_catalog.pg_type s ON s.oid = c.castsource
            JOIN pg_catalog.pg_namespace sn ON sn.oid = s.typnamespace
            JOIN pg_catalog.pg_type t ON t.oid = c.casttarget
            JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
            WHERE c.castcontext = 'i'
              AND sn.nspname = 'pg_catalog'
              AND tn.nspname = 'pg_catalog'
            ",
            &[],
        )
        .context("Failed to load implicit casts")?;
    Ok(crate::_internal::model::cast::CastCatalogue::new(
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("source").context("implicit cast source")?,
                    row.try_get("target").context("implicit cast target")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}

pub(super) fn load_aggregates(
    client: &mut impl GenericClient,
) -> Result<crate::_internal::model::aggregate::AggregateCatalogue> {
    use crate::_internal::model::aggregate::{
        AggregateArg, AggregateCatalogue, AggregateKind, AggregateSignature,
    };

    let rows = client
        .query(
            "
            SELECT
                p.oid AS oid,
                p.proname AS name,
                g.aggkind::text AS kind,
                CASE WHEN g.aggkind = 'n' THEN p.pronargs::int
                     ELSE g.aggnumdirectargs::int END AS direct,
                a.ord AS ord,
                pg_catalog.format_type(a.argtype, NULL) AS arg,
                (t.typcategory = 'P') AS polymorphic
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_catalog.pg_aggregate g ON g.aggfnoid = p.oid
            LEFT JOIN LATERAL unnest(p.proargtypes) WITH ORDINALITY AS a(argtype, ord) ON true
            LEFT JOIN pg_catalog.pg_type t ON t.oid = a.argtype
            WHERE n.nspname = 'pg_catalog'
            ORDER BY p.oid, a.ord
            ",
            &[],
        )
        .context("Failed to load built-in aggregates")?;

    struct Current {
        oid: u32,
        name: String,
        kind: AggregateKind,
        direct: usize,
        arguments: Vec<AggregateArg>,
    }

    let mut entries: Vec<(String, AggregateSignature)> = Vec::new();
    let mut current: Option<Current> = None;
    for row in rows {
        let oid: u32 = row.try_get("oid").context("aggregate oid")?;
        let name: String = row.try_get("name").context("aggregate name")?;
        let kind: String = row.try_get("kind").context("aggregate kind")?;
        let kind = AggregateKind::from_catalog(&kind)
            .with_context(|| format!("unknown aggregate kind '{kind}' for {name}"))?;
        let direct: i32 = row.try_get("direct").context("aggregate direct count")?;
        let argument = match row
            .try_get::<_, Option<String>>("arg")
            .context("aggregate argument")?
        {
            None => None,
            Some(_)
                if row
                    .try_get::<_, Option<bool>>("polymorphic")
                    .context("aggregate polymorphism")?
                    .unwrap_or(false) =>
            {
                Some(AggregateArg::Any)
            }
            Some(spelling) => Some(AggregateArg::Type(spelling)),
        };
        if let Some(current) = current.as_mut()
            && current.oid == oid
        {
            if let Some(argument) = argument {
                current.arguments.push(argument);
            }
            continue;
        }
        if let Some(finished) = current.take() {
            entries.push((
                finished.name,
                AggregateSignature::new(finished.kind, finished.direct, finished.arguments),
            ));
        }
        current = Some(Current {
            oid,
            name,
            kind,
            direct: usize::try_from(direct).context("aggregate direct count")?,
            arguments: argument.into_iter().collect(),
        });
    }
    if let Some(finished) = current {
        entries.push((
            finished.name,
            AggregateSignature::new(finished.kind, finished.direct, finished.arguments),
        ));
    }

    Ok(AggregateCatalogue::new(entries))
}

pub(super) fn load_builtin_types(
    client: &mut impl GenericClient,
) -> Result<crate::_internal::model::builtin_type::BuiltinTypeCatalogue> {
    let rows = client
        .query(
            "
            SELECT
                t.oid,
                t.typname,
                pg_catalog.format_type(t.oid, NULL) AS canonical,
                t.typcategory::text AS category,
                t.typispreferred,
                t.typlen,
                t.typarray,
                t.typmodout <> 0 AS accepts_typmod
            FROM pg_catalog.pg_type t
            JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'pg_catalog'
              AND t.typtype IN ('b', 'r', 'm')
              AND t.typcategory <> 'A';
            ",
            &[],
        )
        .context("Failed to load built-in types")?;

    let types = rows
        .into_iter()
        .map(|row| {
            use crate::_internal::model::builtin_type::{BuiltinType, TypeCategory};
            // `typlen` is negative for variable-length types, so only a
            // positive value states a fixed width.
            let typlen: i16 = row.try_get("typlen").context("built-in type length")?;
            let category: String = row.try_get("category").context("built-in type category")?;
            Ok(BuiltinType {
                oid: Some(row.try_get("oid").context("built-in type oid")?),
                typname: row.try_get("typname").context("built-in type name")?,
                canonical: row
                    .try_get("canonical")
                    .context("built-in type canonical name")?,
                category: TypeCategory::from_catalog(&category),
                preferred: row
                    .try_get("typispreferred")
                    .context("built-in type preferred flag")?,
                fixed_bits: (typlen > 0).then(|| i32::from(typlen) * 8),
                array_oid: match row
                    .try_get::<_, u32>("typarray")
                    .context("built-in type array oid")?
                {
                    0 => None,
                    oid => Some(oid),
                },
                accepts_typmod: row
                    .try_get("accepts_typmod")
                    .context("built-in type typmod flag")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(crate::_internal::model::builtin_type::BuiltinTypeCatalogue::new(types))
}

pub(super) fn load_types(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
) -> Result<std::collections::HashMap<ObjectId, crate::_internal::model::types::TypeState>> {
    // Every `typtype` a user can name in `DROP TYPE` / `ALTER TYPE`. Array
    // types are excluded because PostgreSQL refuses both for them ("cannot
    // alter/drop array type"), so they are never independently addressable.
    let type_predicate = "t.typtype IN ('e', 'd', 'c', 'r', 'm') \
                          OR (t.typtype = 'b' AND t.typelem = 0)";
    let query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            t.typname AS type_name,
            t.typtype::text AS type_kind,
            CASE WHEN t.typtype = 'd'
                THEN pg_catalog.format_type(t.typbasetype, t.typtypmod)
                ELSE NULL
            END AS domain_base_type,
            COALESCE(
                array_agg(e.enumlabel ORDER BY e.enumsortorder)
                    FILTER (WHERE e.enumlabel IS NOT NULL),
                ARRAY[]::text[]
            ) AS enum_labels,
            COALESCE(
                array_agg(a.attname ORDER BY a.attnum)
                    FILTER (WHERE a.attname IS NOT NULL),
                ARRAY[]::text[]
            ) AS composite_field_names,
            range.rngsubtype::regtype::text AS range_subtype,
            CASE WHEN t.typelem <> 0
                 THEN t.typelem::regtype::text
                 ELSE NULL
            END AS element_type,
            COALESCE(
                array_agg(
                    CASE WHEN field_type_ns.nspname <> 'pg_catalog'
                              AND pg_catalog.pg_type_is_visible(a.atttypid)
                         THEN quote_ident(field_type_ns.nspname) || '.'
                              || pg_catalog.format_type(a.atttypid, a.atttypmod)
                         ELSE pg_catalog.format_type(a.atttypid, a.atttypmod)
                    END
                    ORDER BY a.attnum
                )
                    FILTER (WHERE a.attname IS NOT NULL),
                ARRAY[]::text[]
            ) AS composite_field_types
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        LEFT JOIN pg_enum e ON e.enumtypid = t.oid
        LEFT JOIN pg_range range ON range.rngtypid = t.oid
        LEFT JOIN pg_class composite_rel ON composite_rel.oid = t.typrelid
        LEFT JOIN pg_attribute a
          ON a.attrelid = t.typrelid
         AND a.attnum > 0
         AND NOT a.attisdropped
        LEFT JOIN pg_type field_type ON field_type.oid = a.atttypid
        LEFT JOIN pg_namespace field_type_ns ON field_type_ns.oid = field_type.typnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND ({type_predicate})
          AND (t.typtype <> 'c' OR composite_rel.relkind = 'c')
          {schema_filter}
        GROUP BY n.nspname, t.typname, t.typtype, t.typbasetype, t.typtypmod,
                 t.typelem, range.rngsubtype;
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load user-defined enum and domain types")?
        .into_iter()
        .map(|row| {
            let type_kind: String = row.try_get("type_kind").context("type kind")?;
            let kind = match type_kind.as_str() {
                "e" => crate::_internal::model::types::TypeKind::Enum {
                    variants: row.try_get("enum_labels").context("enum labels")?,
                },
                "d" => crate::_internal::model::types::TypeKind::Domain {
                    base_type: row
                        .try_get::<_, Option<String>>("domain_base_type")
                        .context("domain base type")?
                        .context("PostgreSQL omitted the base type for a domain")?,
                    base_type_id: None,
                },
                "r" => crate::_internal::model::types::TypeKind::Range {
                    subtype: row.try_get("range_subtype").context("range subtype")?,
                    subtype_id: None,
                },
                "m" => crate::_internal::model::types::TypeKind::Multirange,
                "b" => crate::_internal::model::types::TypeKind::Base {
                    element: row.try_get("element_type").context("element type")?,
                },
                "c" => {
                    let names: Vec<String> = row
                        .try_get("composite_field_names")
                        .context("composite field names")?;
                    let data_types: Vec<String> = row
                        .try_get("composite_field_types")
                        .context("composite field types")?;
                    if names.len() != data_types.len() {
                        anyhow::bail!("PostgreSQL returned mismatched composite field metadata");
                    }
                    crate::_internal::model::types::TypeKind::Composite {
                        fields: names
                            .into_iter()
                            .zip(data_types)
                            .map(|(name, data_type)| {
                                crate::_internal::model::types::CompositeFieldState {
                                    name,
                                    data_type,
                                    data_type_id: None,
                                }
                            })
                            .collect(),
                    }
                }
                other => anyhow::bail!("unsupported pg_type.typtype '{other}'"),
            };
            let id = ObjectId::new(
                row.try_get::<_, String>("schema_name")
                    .context("type schema")?,
                row.try_get::<_, String>("type_name").context("type name")?,
            );
            Ok((
                id.clone(),
                crate::_internal::model::types::TypeState {
                    id,
                    generation: 0,
                    kind,
                },
            ))
        })
        .collect()
}
