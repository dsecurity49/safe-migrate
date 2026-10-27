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
                t.typmodout <> 0 AS accepts_typmod,
                t.typcollation <> 0 AS collatable
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
                collatable: row
                    .try_get("collatable")
                    .context("built-in type collation flag")?,
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
            pg_catalog.pg_get_userbyid(t.typowner) AS owner_name,
            CASE WHEN t.typtype = 'd'
                THEN pg_catalog.format_type(t.typbasetype, t.typtypmod)
                ELSE NULL
            END AS domain_base_type,
            t.typnotnull AS domain_not_null,
            t.typdefault AS domain_default_text,
            CASE WHEN t.typcollation <> 0 THEN cn.nspname END AS collation_schema,
            CASE WHEN t.typcollation <> 0 THEN c.collname END AS collation_name,
            COALESCE(
                array_agg(e.enumlabel ORDER BY e.enumsortorder)
                    FILTER (WHERE e.enumlabel IS NOT NULL),
                ARRAY[]::text[]
            ) AS enum_labels,
            CASE WHEN t.typtype = 'r'
                 THEN pg_catalog.format_type(range.rngsubtype, NULL)
                 ELSE NULL
            END AS range_subtype,
            CASE WHEN range.rngmultitypid <> 0 THEN mtn.nspname END AS multirange_schema,
            CASE WHEN range.rngmultitypid <> 0 THEN mt.typname END AS multirange_name,
            CASE WHEN range.rngcollation <> 0 THEN rcn.nspname END AS range_collation_schema,
            CASE WHEN range.rngcollation <> 0 THEN rc.collname END AS range_collation_name,
            CASE WHEN range.rngsubopc <> 0 THEN opn.nspname END AS opclass_schema,
            CASE WHEN range.rngsubopc <> 0 THEN opc.opcname END AS opclass_name,
            CASE WHEN range.rngcanonical <> 0
                 THEN range.rngcanonical::regprocedure::text
                 ELSE NULL
            END AS canonical_function,
            CASE WHEN range.rngsubdiff <> 0
                 THEN range.rngsubdiff::regprocedure::text
                 ELSE NULL
            END AS subtype_diff_function,
            CASE WHEN mr.rngtypid IS NOT NULL THEN rn.nspname END AS range_schema,
            CASE WHEN mr.rngtypid IS NOT NULL THEN rt.typname END AS range_name,
            CASE WHEN t.typelem <> 0
                 THEN t.typelem::regtype::text
                 ELSE NULL
            END AS element_type,
            t.typisdefined AS type_is_defined,
            t.typlen AS type_length,
            t.typbyval AS passed_by_value,
            t.typalign::text AS alignment,
            t.typstorage::text AS storage,
            t.typcategory::text AS category,
            t.typispreferred AS preferred,
            t.typdefault AS base_default,
            t.typdelim AS delimiter,
            t.typcollation <> 0 AS collatable,
            t.typinput::regprocedure::text AS input_function,
            t.typoutput::regprocedure::text AS output_function,
            CASE WHEN t.typreceive <> 0
                 THEN t.typreceive::regprocedure::text
                 ELSE NULL
            END AS receive_function,
            CASE WHEN t.typsend <> 0
                 THEN t.typsend::regprocedure::text
                 ELSE NULL
            END AS send_function,
            CASE WHEN t.typmodin <> 0
                 THEN t.typmodin::regprocedure::text
                 ELSE NULL
            END AS typmod_in_function,
            CASE WHEN t.typmodout <> 0
                 THEN t.typmodout::regprocedure::text
                 ELSE NULL
            END AS typmod_out_function,
            CASE WHEN t.typanalyze <> 0
                 THEN t.typanalyze::regprocedure::text
                 ELSE NULL
            END AS analyze_function,
            CASE WHEN t.typsubscript <> 0
                 THEN t.typsubscript::regprocedure::text
                 ELSE NULL
            END AS subscript_function,
            nn.conname AS not_null_constraint
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        LEFT JOIN pg_enum e ON e.enumtypid = t.oid
        LEFT JOIN pg_collation c ON c.oid = t.typcollation
        LEFT JOIN pg_namespace cn ON cn.oid = c.collnamespace
        LEFT JOIN pg_range range ON range.rngtypid = t.oid
        LEFT JOIN pg_type mt ON mt.oid = range.rngmultitypid
        LEFT JOIN pg_namespace mtn ON mtn.oid = mt.typnamespace
        LEFT JOIN pg_collation rc ON rc.oid = range.rngcollation
        LEFT JOIN pg_namespace rcn ON rcn.oid = rc.collnamespace
        LEFT JOIN pg_opclass opc ON opc.oid = range.rngsubopc
        LEFT JOIN pg_namespace opn ON opn.oid = opc.opcnamespace
        LEFT JOIN pg_range mr ON mr.rngmultitypid = t.oid
        LEFT JOIN pg_type rt ON rt.oid = mr.rngtypid
        LEFT JOIN pg_namespace rn ON rn.oid = rt.typnamespace
        LEFT JOIN pg_constraint nn ON nn.contypid = t.oid AND nn.contype = 'n'
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND ({type_predicate})
          AND (t.typtype <> 'c' OR EXISTS (
              SELECT 1 FROM pg_class composite_rel
              WHERE composite_rel.oid = t.typrelid
                AND composite_rel.relkind = 'c'
          ))
          {schema_filter}
        GROUP BY n.nspname, t.typname, t.typtype, t.typowner, t.typbasetype,
                 t.typtypmod, t.typnotnull, t.typdefault, t.typcollation,
                 c.collname, cn.nspname, range.rngsubtype, range.rngmultitypid,
                 mt.typname, mtn.nspname, range.rngcollation, rc.collname,
                 rcn.nspname, range.rngsubopc, opc.opcname, opn.nspname,
                 range.rngcanonical, range.rngsubdiff, mr.rngtypid,
                 rt.typname, rn.nspname, t.typelem, t.typisdefined, t.typlen,
                 t.typbyval, t.typalign, t.typstorage, t.typcategory,
                 t.typispreferred, t.typdelim, t.typinput, t.typoutput,
                 t.typreceive, t.typsend, t.typmodin, t.typmodout,
                 t.typanalyze, t.typsubscript, nn.conname;
        "
    );
    let mut types = client
        .query(&query, &[schema_values])
        .context("Failed to load user-defined types")?
        .into_iter()
        .map(|row| {
            let type_kind: String = row.try_get("type_kind").context("type kind")?;
            let collation = row
                .try_get::<_, Option<String>>("collation_schema")
                .context("type collation schema")?
                .zip(
                    row.try_get::<_, Option<String>>("collation_name")
                        .context("type collation name")?,
                );
            let (collation, collation_id) = match collation {
                Some((schema, name)) => (Some(name.clone()), Some(ObjectId::new(schema, name))),
                None => (None, None),
            };
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
                    collation,
                    collation_id,
                    default: None,
                    default_text: row
                        .try_get("domain_default_text")
                        .context("domain default")?,
                    not_null: row
                        .try_get("domain_not_null")
                        .context("domain not-null flag")?,
                    not_null_constraint: row
                        .try_get("not_null_constraint")
                        .context("domain not-null constraint")?,
                    constraints: Default::default(),
                },
                "r" => {
                    let multirange = row
                        .try_get::<_, Option<String>>("multirange_schema")
                        .context("multirange schema")?
                        .zip(
                            row.try_get::<_, Option<String>>("multirange_name")
                                .context("multirange name")?,
                        )
                        .map(|(schema, name)| ObjectId::new(schema, name));
                    let range_collation = row
                        .try_get::<_, Option<String>>("range_collation_schema")
                        .context("range collation schema")?
                        .zip(
                            row.try_get::<_, Option<String>>("range_collation_name")
                                .context("range collation name")?,
                        );
                    let (range_collation, range_collation_id) = match range_collation {
                        Some((schema, name)) => {
                            (Some(name.clone()), Some(ObjectId::new(schema, name)))
                        }
                        None => (None, None),
                    };
                    let opclass = row
                        .try_get::<_, Option<String>>("opclass_schema")
                        .context("range opclass schema")?
                        .zip(
                            row.try_get::<_, Option<String>>("opclass_name")
                                .context("range opclass name")?,
                        );
                    let (opclass, opclass_id) = match opclass {
                        Some((schema, name)) => {
                            (Some(name.clone()), Some(ObjectId::new(schema, name)))
                        }
                        None => (None, None),
                    };
                    crate::_internal::model::types::TypeKind::Range {
                        subtype: row.try_get("range_subtype").context("range subtype")?,
                        subtype_id: None,
                        multirange,
                        collation: range_collation,
                        collation_id: range_collation_id,
                        opclass,
                        opclass_id,
                        canonical: row
                            .try_get("canonical_function")
                            .context("range canonical function")?,
                        canonical_id: None,
                        subtype_diff: row
                            .try_get("subtype_diff_function")
                            .context("range subtype_diff function")?,
                        subtype_diff_id: None,
                    }
                }
                "m" => {
                    let range = row
                        .try_get::<_, Option<String>>("range_schema")
                        .context("multirange range schema")?
                        .zip(
                            row.try_get::<_, Option<String>>("range_name")
                                .context("multirange range name")?,
                        )
                        .map(|(schema, name)| ObjectId::new(schema, name));
                    crate::_internal::model::types::TypeKind::Multirange { range }
                }
                "b" => {
                    let type_length: i16 = row.try_get("type_length").context("type length")?;
                    let internallength = match type_length {
                        0 => None,
                        -1 => Some(crate::_internal::model::types::BaseTypeLength::Variable),
                        length if length > 0 => Some(
                            crate::_internal::model::types::BaseTypeLength::Fixed(length),
                        ),
                        _ => None,
                    };
                    crate::_internal::model::types::TypeKind::Base {
                        shell: !row
                            .try_get::<_, bool>("type_is_defined")
                            .context("shell type flag")?,
                        options: crate::_internal::model::types::BaseTypeOptions {
                            input: row.try_get("input_function").context("type input")?,
                            output: row.try_get("output_function").context("type output")?,
                            receive: row.try_get("receive_function").context("type receive")?,
                            send: row.try_get("send_function").context("type send")?,
                            typmod_in: row
                                .try_get("typmod_in_function")
                                .context("type typmod_in")?,
                            typmod_out: row
                                .try_get("typmod_out_function")
                                .context("type typmod_out")?,
                            analyze: row.try_get("analyze_function").context("type analyze")?,
                            subscript: row
                                .try_get("subscript_function")
                                .context("type subscript")?,
                            internallength,
                            passed_by_value: row
                                .try_get("passed_by_value")
                                .context("type passed-by-value")?,
                            alignment: row.try_get("alignment").context("type alignment")?,
                            storage: row.try_get("storage").context("type storage")?,
                            like: None,
                            category: row.try_get("category").context("type category")?,
                            preferred: row.try_get("preferred").context("type preferred")?,
                            default: row.try_get("base_default").context("type default")?,
                            element: row.try_get("element_type").context("element type")?,
                            delimiter: row.try_get("delimiter").context("type delimiter")?,
                            collatable: row
                                .try_get("collatable")
                                .context("type collatable flag")?,
                        },
                    }
                }
                "c" => crate::_internal::model::types::TypeKind::Composite { fields: Vec::new() },
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
                    owner: relation_owner_id(
                        row.try_get::<_, String>("owner_name")
                            .context("type owner")?,
                    ),
                    kind,
                },
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()?;

    load_composite_fields(client, schema_values, schema_filter, &mut types)?;
    load_domain_constraints(client, schema_values, schema_filter, &mut types)?;
    Ok(types)
}

fn load_composite_fields(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
    types: &mut std::collections::HashMap<ObjectId, crate::_internal::model::types::TypeState>,
) -> Result<()> {
    let query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            t.typname AS type_name,
            a.attname AS field_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS field_type,
            CASE WHEN a.attcollation <> 0 THEN cn.nspname END AS collation_schema,
            CASE WHEN a.attcollation <> 0 THEN c.collname END AS collation_name
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_class composite_rel ON composite_rel.oid = t.typrelid
        JOIN pg_attribute a
          ON a.attrelid = t.typrelid
         AND a.attnum > 0
         AND NOT a.attisdropped
        LEFT JOIN pg_collation c ON c.oid = a.attcollation
        LEFT JOIN pg_namespace cn ON cn.oid = c.collnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND t.typtype = 'c'
          AND composite_rel.relkind = 'c'
          {schema_filter}
        ORDER BY n.nspname, t.typname, a.attnum;
        "
    );
    for row in client
        .query(&query, &[schema_values])
        .context("Failed to load composite type fields")?
    {
        let id = ObjectId::new(
            row.try_get::<_, String>("schema_name")
                .context("composite field type schema")?,
            row.try_get::<_, String>("type_name")
                .context("composite field type name")?,
        );
        let Some(state) = types.get_mut(&id) else {
            continue;
        };
        let crate::_internal::model::types::TypeKind::Composite { fields } = &mut state.kind else {
            continue;
        };
        let collation = row
            .try_get::<_, Option<String>>("collation_schema")
            .context("composite field collation schema")?
            .zip(
                row.try_get::<_, Option<String>>("collation_name")
                    .context("composite field collation name")?,
            );
        let (collation, collation_id) = match collation {
            Some((schema, name)) => (Some(name.clone()), Some(ObjectId::new(schema, name))),
            None => (None, None),
        };
        fields.push(crate::_internal::model::types::CompositeFieldState {
            name: row.try_get("field_name").context("composite field name")?,
            data_type: row.try_get("field_type").context("composite field type")?,
            data_type_id: None,
            collation,
            collation_id,
        });
    }
    Ok(())
}

fn load_domain_constraints(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter: &str,
    types: &mut std::collections::HashMap<ObjectId, crate::_internal::model::types::TypeState>,
) -> Result<()> {
    let query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            t.typname AS type_name,
            c.conname AS constraint_name,
            c.convalidated AS validated,
            pg_catalog.pg_get_constraintdef(c.oid, false) AS definition,
            pg_catalog.pg_get_expr(c.conbin, 0, false) AS expression_text
        FROM pg_constraint c
        JOIN pg_type t ON t.oid = c.contypid
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE c.contype = 'c'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter}
        ORDER BY n.nspname, t.typname, c.conname;
        "
    );
    for row in client
        .query(&query, &[schema_values])
        .context("Failed to load domain constraints")?
    {
        let id = ObjectId::new(
            row.try_get::<_, String>("schema_name")
                .context("domain constraint schema")?,
            row.try_get::<_, String>("type_name")
                .context("domain constraint type name")?,
        );
        let Some(state) = types.get_mut(&id) else {
            continue;
        };
        let crate::_internal::model::types::TypeKind::Domain { constraints, .. } = &mut state.kind
        else {
            continue;
        };
        let name: String = row
            .try_get("constraint_name")
            .context("domain constraint name")?;
        constraints.insert(
            name.clone(),
            crate::_internal::model::types::DomainConstraintState {
                name,
                expression: None,
                expression_text: row
                    .try_get("expression_text")
                    .context("domain constraint expression")?,
                definition: row
                    .try_get("definition")
                    .context("domain constraint definition")?,
                validated: row
                    .try_get("validated")
                    .context("domain constraint validation")?,
            },
        );
    }
    Ok(())
}
