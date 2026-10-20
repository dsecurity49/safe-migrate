use super::*;

pub(super) fn load_constraints(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<crate::_internal::model::constraint::ConstraintState>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            con.contype::text AS constraint_type,
            con.convalidated AS validated,
            CASE WHEN con.contype = 'c'
                 THEN pg_get_expr(con.conbin, con.conrelid, false)
                 ELSE NULL
            END AS definition,
            NULLIF(backing_n.nspname, '') AS backing_index_schema,
            NULLIF(backing.relname, '') AS backing_index_name
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_class backing ON backing.oid = con.conindid
        LEFT JOIN pg_namespace backing_n ON backing_n.oid = backing.relnamespace
        WHERE con.contype IN ('c', 'f', 'p', 'u', 'x', 'n')
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load table constraints from pg_constraint")?
        .into_iter()
        .map(|row| {
            let constraint_type: String =
                row.try_get("constraint_type").context("constraint type")?;
            let kind = match constraint_type.as_str() {
                "c" => crate::_internal::model::constraint::ConstraintKind::Check,
                "f" => crate::_internal::model::constraint::ConstraintKind::ForeignKey,
                "p" => crate::_internal::model::constraint::ConstraintKind::PrimaryKey,
                "u" => crate::_internal::model::constraint::ConstraintKind::Unique,
                "x" => crate::_internal::model::constraint::ConstraintKind::Exclusion,
                "n" => crate::_internal::model::constraint::ConstraintKind::NotNull,
                other => anyhow::bail!("unsupported pg_constraint.contype '{other}'"),
            };
            // `conindid` has two different PostgreSQL meanings: key and
            // exclusion constraints own their supporting index, while a
            // foreign key stores the referenced key index.  ConstraintState's
            // backing index is intentionally only the former; retaining the
            // FK's referenced index here would make a valid cross-table cache
            // look internally inconsistent during V8 validation.
            let backing_index = if matches!(
                kind,
                crate::_internal::model::constraint::ConstraintKind::PrimaryKey
                    | crate::_internal::model::constraint::ConstraintKind::Unique
                    | crate::_internal::model::constraint::ConstraintKind::Exclusion
            ) {
                row.try_get::<_, Option<String>>("backing_index_schema")
                    .context("constraint backing index schema")?
                    .zip(
                        row.try_get::<_, Option<String>>("backing_index_name")
                            .context("constraint backing index name")?,
                    )
                    .map(|(schema, name)| ObjectId::new(schema, name))
            } else {
                None
            };
            Ok(crate::_internal::model::constraint::ConstraintState {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint table name")?,
                ),
                name: row.try_get("constraint_name").context("constraint name")?,
                kind,
                validated: row
                    .try_get("validated")
                    .context("constraint validation state")?,
                definition: row.try_get("definition").context("constraint definition")?,
                backing_index,
            })
        })
        .collect()
}

pub(super) fn load_constraint_keys(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<ConstraintKeyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            (con.contype = 'p') AS is_primary,
            ARRAY(
                SELECT a.attname
                FROM unnest(con.conkey) WITH ORDINALITY AS key_column(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = con.conrelid
                 AND a.attnum = key_column.attnum
                 AND NOT a.attisdropped
                ORDER BY key_column.ordinality
            ) AS columns
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE con.contype IN ('p', 'u', 'n')
          AND c.relkind IN ('r', 'p', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load primary and unique key columns from pg_constraint")?
        .into_iter()
        .map(|row| {
            Ok(ConstraintKeyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint-key table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint-key table name")?,
                ),
                constraint_name: row
                    .try_get("constraint_name")
                    .context("constraint-key name")?,
                columns: row.try_get("columns").context("constraint-key columns")?,
                is_primary: row
                    .try_get("is_primary")
                    .context("constraint-key primary flag")?,
            })
        })
        .collect()
}

pub(super) fn load_constraint_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<ConstraintDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            con.conname AS constraint_name,
            ARRAY(
                SELECT DISTINCT names.attname
                FROM (
                    SELECT a.attname
                    FROM pg_depend d
                    JOIN pg_attribute a
                      ON a.attrelid = d.refobjid
                     AND a.attnum = d.refobjsubid
                     AND NOT a.attisdropped
                    WHERE d.classid = 'pg_constraint'::regclass
                      AND d.objid = con.oid
                      AND d.refclassid = 'pg_class'::regclass
                      AND d.refobjid = con.conrelid
                      AND d.refobjsubid > 0
                      AND d.deptype = 'n'
                    UNION ALL
                    SELECT a.attname
                    FROM unnest(con.conkey) AS key(attnum)
                    JOIN pg_attribute a
                      ON a.attrelid = con.conrelid
                     AND a.attnum = key.attnum
                     AND NOT a.attisdropped
                ) AS names
                ORDER BY names.attname
            ) AS dependency_columns
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE con.contype IN ('c', 'x')
          AND c.relkind IN ('r', 'p', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load constraint expression dependencies")?
        .into_iter()
        .map(|row| {
            Ok(ConstraintDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("constraint dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("constraint dependency table name")?,
                ),
                constraint_name: row
                    .try_get("constraint_name")
                    .context("constraint dependency name")?,
                columns: row
                    .try_get("dependency_columns")
                    .context("constraint dependency columns")?,
            })
        })
        .collect()
}

pub(super) fn load_generated_column_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<GeneratedColumnDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            a.attname AS column_name,
            source_a.attname AS depends_on_column
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        JOIN pg_depend d
          ON ((d.classid = 'pg_attrdef'::regclass AND d.objid = ad.oid)
              OR (d.classid = 'pg_class'::regclass
                  AND d.objid = a.attrelid
                  AND d.objsubid = a.attnum))
         AND d.refclassid = 'pg_class'::regclass
         AND d.refobjsubid > 0
        JOIN pg_attribute source_a
          ON source_a.attrelid = d.refobjid
         AND source_a.attnum = d.refobjsubid
         AND NOT source_a.attisdropped
         AND source_a.attrelid = a.attrelid
         AND source_a.attnum <> a.attnum
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND a.attgenerated = 's'
          AND c.relkind IN ('r', 'p', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname, a.attname, source_a.attname;
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load generated-column dependencies")?
        .into_iter()
        .map(|row| {
            Ok(GeneratedColumnDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("generated dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("generated dependency table name")?,
                ),
                column_name: row
                    .try_get("column_name")
                    .context("generated dependency column")?,
                depends_on_column: row
                    .try_get("depends_on_column")
                    .context("generated dependency source column")?,
            })
        })
        .collect()
}

pub(super) fn load_default_sequence_dependencies(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
    schema_filter_with_fk: &str,
) -> Result<Vec<DefaultSequenceDependencyCache>> {
    let query = format!(
        "
        SELECT
            n.nspname AS table_schema,
            c.relname AS table_name,
            a.attname AS column_name,
            seqn.nspname AS sequence_schema,
            seq.relname AS sequence_name
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        JOIN pg_depend d
          ON d.classid = 'pg_attrdef'::regclass
         AND d.objid = ad.oid
         AND d.refclassid = 'pg_class'::regclass
         AND d.refobjsubid = 0
         AND d.deptype = 'n'
        JOIN pg_class seq ON seq.oid = d.refobjid AND seq.relkind = 'S'
        JOIN pg_namespace seqn ON seqn.oid = seq.relnamespace
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND a.attgenerated = ''
          AND c.relkind IN ('r', 'p', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname, a.attname, seqn.nspname, seq.relname;
        "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load default sequence dependencies")?
        .into_iter()
        .map(|row| {
            Ok(DefaultSequenceDependencyCache {
                table_id: ObjectId::new(
                    row.try_get::<_, String>("table_schema")
                        .context("default dependency table schema")?,
                    row.try_get::<_, String>("table_name")
                        .context("default dependency table name")?,
                ),
                column_name: row
                    .try_get("column_name")
                    .context("default dependency column")?,
                sequence_id: ObjectId::new(
                    row.try_get::<_, String>("sequence_schema")
                        .context("default dependency sequence schema")?,
                    row.try_get::<_, String>("sequence_name")
                        .context("default dependency sequence name")?,
                ),
            })
        })
        .collect()
}

pub(super) fn load_foreign_keys(
    client: &mut impl GenericClient,
    schemas: Option<&[String]>,
    schema_values: &Option<Vec<String>>,
    schema_filter_n1_or_n2: &str,
) -> Result<Vec<ForeignKeyCache>> {
    let query = format!(
        "
        SELECT
            c.conname AS constraint_name,
            n1.nspname AS from_schema, t1.relname AS from_table,
            n2.nspname AS to_schema, t2.relname AS to_table,
            ARRAY(
                SELECT a.attname
                FROM unnest(c.conkey) WITH ORDINALITY AS source_key(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = c.conrelid
                 AND a.attnum = source_key.attnum
                 AND NOT a.attisdropped
                ORDER BY source_key.ordinality
            ) AS from_columns,
            ARRAY(
                SELECT a.attname
                FROM unnest(c.confkey) WITH ORDINALITY AS target_key(attnum, ordinality)
                JOIN pg_attribute a
                  ON a.attrelid = c.confrelid
                 AND a.attnum = target_key.attnum
                 AND NOT a.attisdropped
                ORDER BY target_key.ordinality
            ) AS to_columns,
            ARRAY(
                SELECT format('%s.%s(%s,%s)', op_ns.nspname, op.oprname,
                              pg_catalog.format_type(op.oprleft, NULL),
                              pg_catalog.format_type(op.oprright, NULL))
                FROM unnest(c.conpfeqop) WITH ORDINALITY AS selected_operator(oid, ordinality)
                JOIN pg_operator op ON op.oid = selected_operator.oid
                JOIN pg_namespace op_ns ON op_ns.oid = op.oprnamespace
                ORDER BY selected_operator.ordinality
            ) AS pk_fk_equality_operators,
            ARRAY(
                SELECT format('%s.%s(%s,%s)', op_ns.nspname, op.oprname,
                              pg_catalog.format_type(op.oprleft, NULL),
                              pg_catalog.format_type(op.oprright, NULL))
                FROM unnest(c.conppeqop) WITH ORDINALITY AS selected_operator(oid, ordinality)
                JOIN pg_operator op ON op.oid = selected_operator.oid
                JOIN pg_namespace op_ns ON op_ns.oid = op.oprnamespace
                ORDER BY selected_operator.ordinality
            ) AS pk_pk_equality_operators,
            ARRAY(
                SELECT format('%s.%s(%s,%s)', op_ns.nspname, op.oprname,
                              pg_catalog.format_type(op.oprleft, NULL),
                              pg_catalog.format_type(op.oprright, NULL))
                FROM unnest(c.conffeqop) WITH ORDINALITY AS selected_operator(oid, ordinality)
                JOIN pg_operator op ON op.oid = selected_operator.oid
                JOIN pg_namespace op_ns ON op_ns.oid = op.oprnamespace
                ORDER BY selected_operator.ordinality
            ) AS fk_fk_equality_operators
        FROM pg_constraint c
        JOIN pg_class t1 ON t1.oid = c.conrelid
        JOIN pg_namespace n1 ON n1.oid = t1.relnamespace
        JOIN pg_class t2 ON t2.oid = c.confrelid
        JOIN pg_namespace n2 ON n2.oid = t2.relnamespace
        WHERE c.contype = 'f'
        {schema_filter_n1_or_n2};
    "
    );
    client
        .query(&query, &[schema_values])
        .context("Failed to load foreign keys from pg_constraint")?
        .into_iter()
        .map(|row| {
            let constraint_name: String = row
                .try_get("constraint_name")
                .context("foreign-key constraint name")?;
            let from_schema: String = row
                .try_get("from_schema")
                .context("foreign-key source schema")?;
            let from_table: String = row
                .try_get("from_table")
                .context("foreign-key source table")?;
            let to_schema: String = row
                .try_get("to_schema")
                .context("foreign-key target schema")?;
            let to_table: String = row
                .try_get("to_table")
                .context("foreign-key target table")?;
            let from_columns: Vec<String> = row
                .try_get("from_columns")
                .context("foreign-key source columns")?;
            let to_columns: Vec<String> = row
                .try_get("to_columns")
                .context("foreign-key target columns")?;
            let pk_fk_equality_operators: Vec<String> = row
                .try_get("pk_fk_equality_operators")
                .context("foreign-key PK/FK equality operators")?;
            let pk_pk_equality_operators: Vec<String> = row
                .try_get("pk_pk_equality_operators")
                .context("foreign-key PK/PK equality operators")?;
            let fk_fk_equality_operators: Vec<String> = row
                .try_get("fk_fk_equality_operators")
                .context("foreign-key FK/FK equality operators")?;
            if let Some(scoped_schemas) = schemas
                && (!scoped_schemas.contains(&from_schema)
                    || !scoped_schemas.contains(&to_schema))
            {
                let (out_of_scope_schema, out_of_scope_table) =
                    if !scoped_schemas.contains(&from_schema) {
                        (&from_schema, &from_table)
                    } else {
                        (&to_schema, &to_table)
                    };
                eprintln!(
                    "[WARN] Foreign key '{}' crosses schema boundary. Table '{}.{}' was pulled into cache as a dependency to evaluate cross-team locks.",
                    constraint_name, out_of_scope_schema, out_of_scope_table
                );
            }
            Ok(ForeignKeyCache {
                constraint_name,
                from_table: ObjectId::new(from_schema, from_table),
                to_table: ObjectId::new(to_schema, to_table),
                from_columns,
                to_columns,
                pk_fk_equality_operators,
                pk_pk_equality_operators,
                fk_fk_equality_operators,
            })
        })
        .collect()
}

pub(super) fn load_index_attachments(
    client: &mut impl GenericClient,
    schema_values: &Option<Vec<String>>,
) -> Result<Vec<IndexAttachmentCache>> {
    let query = r#"
        SELECT
            child_ns.nspname AS child_schema,
            child.relname AS child_name,
            parent_ns.nspname AS parent_schema,
            parent.relname AS parent_name
        FROM pg_inherits inh
        JOIN pg_class child ON child.oid = inh.inhrelid
        JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
        JOIN pg_class parent ON parent.oid = inh.inhparent
        JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
        WHERE child.relkind IN ('i', 'I')
          AND parent.relkind = 'I'
          AND child_ns.nspname NOT IN ('pg_catalog', 'information_schema')
          AND parent_ns.nspname NOT IN ('pg_catalog', 'information_schema')
          AND (
              $1::text[] IS NULL
              OR child_ns.nspname = ANY($1)
              OR parent_ns.nspname = ANY($1)
          )
        ORDER BY child_ns.nspname, child.relname
    "#;
    let rows = client
        .query(query, &[schema_values])
        .context("Failed to load index attachments from pg_inherits")?;
    rows.iter()
        .map(|row| {
            Ok(IndexAttachmentCache {
                child: ObjectId::new(
                    row.try_get::<_, String>("child_schema")
                        .context("attached index schema")?,
                    row.try_get::<_, String>("child_name")
                        .context("attached index name")?,
                ),
                parent: ObjectId::new(
                    row.try_get::<_, String>("parent_schema")
                        .context("parent index schema")?,
                    row.try_get::<_, String>("parent_name")
                        .context("parent index name")?,
                ),
            })
        })
        .collect()
}
