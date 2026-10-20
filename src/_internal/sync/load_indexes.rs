use super::*;

pub(super) fn load_indexes(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_nt: &str,
    pg_version_num: u32,
) -> Result<Vec<IndexCache>> {
    // `indnullsnotdistinct` exists from PostgreSQL 15; a layout without it can
    // only hold indexes that are NULLS DISTINCT, so the literal is exact.
    let nulls_not_distinct = if pg_version_num >= 150_000 {
        "x.indnullsnotdistinct"
    } else {
        "FALSE"
    };
    let query = format!(
        "
        SELECT
            n_i.nspname AS index_schema, i.relname AS index_name,
            n_t.nspname AS table_schema, t.relname AS table_name,
            am.amname AS using_method,
            x.indisvalid AS is_valid,
            x.indisready AS is_ready,
            x.indislive AS is_live,
            x.indisunique AS is_unique,
            x.indimmediate AS is_immediate,
            x.indpred IS NOT NULL AS has_predicate,
            ARRAY(
                SELECT a.attname
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key_part(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = key_part.attnum
                 AND NOT a.attisdropped
                WHERE key_part.ordinality <= x.indnkeyatts
                ORDER BY key_part.ordinality
            ) AS key_columns,
            ARRAY(
                SELECT a.attname
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS included_part(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = included_part.attnum
                 AND NOT a.attisdropped
                WHERE included_part.ordinality > x.indnkeyatts
                ORDER BY included_part.ordinality
            ) AS included_columns,
            ARRAY(
                SELECT a.attname
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = x.indkey[k.ord - 1]
                 AND NOT a.attisdropped
                ORDER BY k.ord
            ) AS key_attnames,
            ARRAY(
                SELECT CASE
                    WHEN opc.opcdefault AND opc.opcmethod = i.relam THEN true
                    ELSE false
                END
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_opclass opc ON opc.oid = x.indclass[k.ord - 1]
                ORDER BY k.ord
            ) AS key_opclass_defaults,
            ARRAY(
                SELECT nf.nspname
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_opclass opc ON opc.oid = x.indclass[k.ord - 1]
                LEFT JOIN pg_opfamily f ON f.oid = opc.opcfamily
                LEFT JOIN pg_namespace nf ON nf.oid = f.opfnamespace
                ORDER BY k.ord
            ) AS key_opfamily_schemas,
            ARRAY(
                SELECT f.opfname
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_opclass opc ON opc.oid = x.indclass[k.ord - 1]
                LEFT JOIN pg_opfamily f ON f.oid = opc.opcfamily
                ORDER BY k.ord
            ) AS key_opfamily_names,
            ARRAY(
                SELECT CASE
                    WHEN x.indcollation[k.ord - 1] = 0 THEN 'not_collatable'
                    WHEN x.indkey[k.ord - 1] <> 0
                         AND x.indcollation[k.ord - 1] = a.attcollation THEN 'derived'
                    -- An expression key with the database default collation is
                    -- the collation the expression inherits, not a choice.
                    WHEN x.indkey[k.ord - 1] = 0
                         AND x.indcollation[k.ord - 1] = 100 THEN 'derived'
                    ELSE 'resolved'
                END
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = x.indkey[k.ord - 1]
                ORDER BY k.ord
            ) AS key_collation_kinds,
            ARRAY(
                SELECT CASE
                    WHEN x.indcollation[k.ord - 1] = 0 THEN NULL
                    WHEN x.indkey[k.ord - 1] <> 0
                         AND x.indcollation[k.ord - 1] = a.attcollation THEN NULL
                    WHEN x.indkey[k.ord - 1] = 0
                         AND x.indcollation[k.ord - 1] = 100 THEN NULL
                    ELSE nc.nspname
                END
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_collation coll ON coll.oid = x.indcollation[k.ord - 1]
                LEFT JOIN pg_namespace nc ON nc.oid = coll.collnamespace
                LEFT JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = x.indkey[k.ord - 1]
                ORDER BY k.ord
            ) AS key_collation_schemas,
            ARRAY(
                SELECT CASE
                    WHEN x.indcollation[k.ord - 1] = 0 THEN NULL
                    WHEN x.indkey[k.ord - 1] <> 0
                         AND x.indcollation[k.ord - 1] = a.attcollation THEN NULL
                    WHEN x.indkey[k.ord - 1] = 0
                         AND x.indcollation[k.ord - 1] = 100 THEN NULL
                    ELSE coll.collname
                END
                FROM generate_series(1, x.indnkeyatts) AS k(ord)
                LEFT JOIN pg_collation coll ON coll.oid = x.indcollation[k.ord - 1]
                LEFT JOIN pg_attribute a
                  ON a.attrelid = x.indrelid
                 AND a.attnum = x.indkey[k.ord - 1]
                ORDER BY k.ord
            ) AS key_collation_names,
            ARRAY(
                SELECT a.attname
                FROM pg_depend d
                JOIN pg_attribute a
                  ON a.attrelid = d.refobjid
                 AND a.attnum = d.refobjsubid
                 AND NOT a.attisdropped
                WHERE d.classid = 'pg_class'::regclass
                  AND d.objid = x.indexrelid
                  AND d.refclassid = 'pg_class'::regclass
                  AND d.refobjid = x.indrelid
                  AND d.refobjsubid > 0
                ORDER BY a.attnum
            ) AS dependency_columns,
            EXISTS (
                SELECT 1
                FROM unnest(x.indkey::smallint[]) WITH ORDINALITY AS key_part(attnum, ordinality)
                WHERE key_part.ordinality <= x.indnkeyatts
                  AND key_part.attnum = 0
            ) AS has_expression_keys,
            COALESCE(
                (
                    SELECT array_agg(o.flags ORDER BY o.ord)
                    FROM unnest(x.indoption::smallint[])
                        WITH ORDINALITY AS o(flags, ord)
                    WHERE o.ord <= x.indnkeyatts
                ),
                ARRAY[]::smallint[]
            ) AS indoption_bits,
            pg_catalog.pg_indexam_has_property(am.oid, 'can_order') AS am_can_order,
            {nulls_not_distinct} AS nulls_not_distinct
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_am am ON am.oid = i.relam
        JOIN pg_namespace n_i ON n_i.oid = i.relnamespace
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n_t ON n_t.oid = t.relnamespace
        WHERE n_i.nspname !~ '^pg_'
          AND n_i.nspname <> 'information_schema'
          AND n_t.nspname !~ '^pg_'
          AND n_t.nspname <> 'information_schema'
        {schema_filter_nt};
    "
    );
    let rows = client
        .query(&query, &[schema_values])
        .context("Failed to load index definitions from pg_index")?;
    let mut indexes = Vec::with_capacity(rows.len());
    for row in rows {
        let index_schema: String = row.try_get("index_schema").context("index schema")?;
        let table_schema: String = row
            .try_get("table_schema")
            .context("indexed table schema")?;
        if is_system_schema(&index_schema) || is_system_schema(&table_schema) {
            continue;
        }
        let key_columns: Vec<String> = row.try_get("key_columns").context("index key columns")?;
        let included_columns: Vec<String> = row
            .try_get("included_columns")
            .context("index included columns")?;
        let key_attnames: Vec<Option<String>> =
            row.try_get("key_attnames").context("index key attnames")?;
        let key_opclass_defaults: Vec<bool> = row
            .try_get("key_opclass_defaults")
            .context("index key default opclass flags")?;
        let key_opfamily_schemas: Vec<Option<String>> = row
            .try_get("key_opfamily_schemas")
            .context("index key opfamily schemas")?;
        let key_opfamily_names: Vec<Option<String>> = row
            .try_get("key_opfamily_names")
            .context("index key opfamily names")?;
        let key_collation_kinds: Vec<String> = row
            .try_get("key_collation_kinds")
            .context("index key collation kinds")?;
        let key_collation_schemas: Vec<Option<String>> = row
            .try_get("key_collation_schemas")
            .context("index key collation schemas")?;
        let key_collation_names: Vec<Option<String>> = row
            .try_get("key_collation_names")
            .context("index key collation names")?;
        let indoption_bits: Vec<i16> = row.try_get("indoption_bits").context("index sort bits")?;
        let am_can_order: bool = row.try_get("am_can_order").context("index access method")?;
        let keys = key_attnames
            .iter()
            .enumerate()
            .map(|(ord, attname)| {
                synced_index_key(
                    attname.as_ref(),
                    key_opclass_defaults.get(ord).copied().unwrap_or(false),
                    key_opfamily_schemas.get(ord).and_then(Option::as_deref),
                    key_opfamily_names.get(ord).and_then(Option::as_deref),
                    key_collation_kinds.get(ord).map(String::as_str),
                    key_collation_schemas.get(ord).and_then(Option::as_deref),
                    key_collation_names.get(ord).and_then(Option::as_deref),
                    indoption_bits.get(ord).copied(),
                    am_can_order,
                )
            })
            .collect::<Vec<_>>();
        let definition = build_index_definition(
            row.try_get("using_method").context("index access method")?,
            keys,
            &included_columns,
            row.try_get("is_unique").context("index uniqueness")?,
            row.try_get("has_predicate")
                .context("index predicate flag")?,
            row.try_get("nulls_not_distinct")
                .context("index null treatment")?,
            row.try_get("is_valid").context("index validity flag")?,
            row.try_get("is_ready").context("index readiness flag")?,
            row.try_get("is_live").context("index liveness flag")?,
        );
        let mut dependency_columns: Vec<String> = row
            .try_get("dependency_columns")
            .context("index dependency columns")?;
        // pg_depend records expression/predicate references, but PostgreSQL
        // does not consistently emit ordinary key/include columns for every
        // index shape.  Those columns are nevertheless guaranteed dependencies
        // for a simple index; make that invariant explicit at hydration rather
        // than allowing an incomplete vector to reach the state machine.
        for column in key_columns.iter().chain(&included_columns) {
            if !dependency_columns.contains(column) {
                dependency_columns.push(column.clone());
            }
        }
        indexes.push(IndexCache {
            index_id: ObjectId::new(
                index_schema,
                row.try_get::<_, String>("index_name")
                    .context("index name")?,
            ),
            table_id: ObjectId::new(
                table_schema,
                row.try_get::<_, String>("table_name")
                    .context("indexed table name")?,
            ),
            definition,
            dependency_columns,
            dependency_columns_known: true,
            is_immediate: row
                .try_get("is_immediate")
                .context("index immediacy flag")?,
        });
    }
    Ok(indexes)
}

///
/// Only what a migration can actually declare is kept. Arrays are excluded
/// because `typarray` plus `[]` already describes them, composites because a
/// table's row type belongs to the relation cache, and pseudo-types because
/// `format_type` already returns their `typname`, so they need no mapping.
///
/// Arrays are identified by `typcategory`, not `typelem`: `name`, `box`,
/// `line`, `lseg` and `point` all carry a non-zero `typelem` recording their
/// array linkage while being ordinary declarable types themselves.
///
/// Must run after the connection pins `search_path` to `pg_catalog`, otherwise
/// `format_type` schema-qualifies every name.
/// Whether every key of an index uses the default sort order.
///
/// The bits are normalized through [`IndexOrder`] rather than tested for zero,
/// because `DESC NULLS FIRST` is stored as `3` and is the same order as `0`.
/// They are also ignored entirely when the access method cannot order, since
/// `indoption` bits are access-method specific.
/// One key's operator-class identity from the catalog: the resolved family,
/// plus whether PostgreSQL chose it as the access method's default.
pub(super) fn synced_opclass(
    is_default: bool,
    family_schema: Option<&str>,
    family_name: Option<&str>,
) -> KeyOpclass {
    match (family_schema, family_name) {
        (Some(schema), Some(name)) => {
            let family = ResolvedName {
                schema: schema.to_string(),
                name: name.to_string(),
            };
            if is_default {
                KeyOpclass::Default(Some(family))
            } else {
                KeyOpclass::Explicit(family)
            }
        }
        // `pg_opfamily` cannot be missing for a live index; a gap stays
        // unknown rather than becoming a false difference.
        _ => KeyOpclass::Unresolved,
    }
}

/// One key's collation identity from the catalog.
pub(super) fn synced_collation(
    kind: Option<&str>,
    schema: Option<&str>,
    name: Option<&str>,
) -> KeyCollation {
    match kind {
        Some("not_collatable") => KeyCollation::NotCollatable,
        Some("derived") => KeyCollation::Derived,
        Some("resolved") => match (schema, name) {
            (Some(schema), Some(name)) => KeyCollation::Resolved(ResolvedName {
                schema: schema.to_string(),
                name: name.to_string(),
            }),
            _ => KeyCollation::Unresolved,
        },
        _ => KeyCollation::Unresolved,
    }
}

/// Build a key's description from the parallel catalog arrays.
///
/// A NULL attname is an expression: `indkey` records it as 0 and PostgreSQL
/// stores no identity for it, so the key is recorded as an expression and
/// never compared by content.
#[allow(clippy::too_many_arguments)]
pub(super) fn synced_index_key(
    attname: Option<&String>,
    opclass_default: bool,
    opfamily_schema: Option<&str>,
    opfamily_name: Option<&str>,
    collation_kind: Option<&str>,
    collation_schema: Option<&str>,
    collation_name: Option<&str>,
    bits: Option<i16>,
    can_order: bool,
) -> IndexKey {
    IndexKey {
        kind: match attname {
            Some(name) => IndexKeyKind::Column(name.clone()),
            None => IndexKeyKind::Expression(None),
        },
        opclass: synced_opclass(opclass_default, opfamily_schema, opfamily_name),
        collation: synced_collation(collation_kind, collation_schema, collation_name),
        order: IndexOrder::from_indoption(bits.unwrap_or(0) as u16, can_order),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_index_definition(
    method: String,
    keys: Vec<IndexKey>,
    included_attnames: &[String],
    unique: bool,
    predicate: bool,
    nulls_not_distinct: bool,
    valid: bool,
    ready: bool,
    live: bool,
) -> IndexDefinition {
    let expression_keys = keys
        .iter()
        .filter(|key| matches!(key.kind, IndexKeyKind::Expression(_)))
        .count();
    IndexDefinition {
        method: Some(method),
        keys,
        included: included_attnames
            .iter()
            .map(|name| IndexKey::column(name.clone()))
            .collect(),
        expression_keys,
        unique,
        nulls_not_distinct: Some(nulls_not_distinct),
        predicate: if predicate {
            IndexPredicate::Opaque
        } else {
            IndexPredicate::None
        },
        unestablished: false,
        valid,
        ready,
        live,
    }
}

pub(super) fn load_opclasses(
    client: &mut impl GenericClient,
) -> Result<crate::_internal::model::opclass::OpclassCatalogue> {
    let rows = client
        .query(
            "
            SELECT
                n.nspname AS namespace,
                o.opcname AS name,
                t.typname AS intype,
                ARRAY(
                    SELECT pg_catalog.format_type(t.oid, NULL)
                    UNION ALL
                    SELECT t.typname
                ) AS aliases,
                am.amname AS method,
                o.opcdefault AS is_default,
                fn.nspname AS family_namespace,
                f.opfname AS family_name
            FROM pg_catalog.pg_opclass o
            JOIN pg_catalog.pg_namespace n ON n.oid = o.opcnamespace
            JOIN pg_catalog.pg_type t ON t.oid = o.opcintype
            JOIN pg_catalog.pg_am am ON am.oid = o.opcmethod
            JOIN pg_catalog.pg_opfamily f ON f.oid = o.opcfamily
            JOIN pg_catalog.pg_namespace fn ON fn.oid = f.opfnamespace
            ",
            &[],
        )
        .context("Failed to load operator classes")?;
    Ok(
        crate::_internal::model::opclass::OpclassCatalogue::from_entries(
            rows.into_iter()
                .map(|row| {
                    Ok(crate::_internal::model::opclass::OpclassEntry {
                        name: row.try_get("name").context("operator class name")?,
                        namespace: row.try_get("namespace").context("operator class schema")?,
                        family: ResolvedName {
                            schema: row
                                .try_get("family_namespace")
                                .context("operator family schema")?,
                            name: row.try_get("family_name").context("operator family name")?,
                        },
                        intype: row.try_get("intype").context("operator class input type")?,
                        aliases: row
                            .try_get("aliases")
                            .context("operator class input type aliases")?,
                        method: row
                            .try_get("method")
                            .context("operator class access method")?,
                        is_default: row
                            .try_get("is_default")
                            .context("operator class default flag")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    )
}

pub(super) fn load_collations(
    client: &mut impl GenericClient,
) -> Result<crate::_internal::model::collation::CollationCatalogue> {
    let rows = client
        .query(
            "
            SELECT
                n.nspname AS schema,
                c.collname AS name
            FROM pg_catalog.pg_collation c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.collnamespace
            ",
            &[],
        )
        .context("Failed to load collations")?;
    Ok(
        crate::_internal::model::collation::CollationCatalogue::from_entries(
            rows.into_iter()
                .map(|row| {
                    Ok(ResolvedName {
                        schema: row.try_get("schema").context("collation schema")?,
                        name: row.try_get("name").context("collation name")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    )
}
