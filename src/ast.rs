use crate::error::{Result, SafeMigrateError};
use crate::model::{AlterAction, MigrationOp, SpannedOp};
use crate::resolve::{extract_index_identity, extract_table_identity, normalize_ident};
use squawk_syntax::ast::{self, AstNode};

fn extract_alter_actions(alter_table: &ast::AlterTable) -> Vec<AlterAction> {
    alter_table
        .actions()
        .map(|action| match action {
            ast::AlterTableAction::AddColumn(_) => AlterAction::AddColumn,
            ast::AlterTableAction::DropColumn(_) => AlterAction::DropColumn,
            ast::AlterTableAction::AlterColumn(_) => AlterAction::AlterColumnUnspecified,
            _ => AlterAction::Other,
        })
        .collect()
}

pub fn parse_and_classify(source_file: ast::SourceFile) -> Result<Vec<SpannedOp>> {
    let mut ops = Vec::new();

    for stmt in source_file.stmts() {
        let syntax = stmt.syntax();
        let range = syntax.text_range();
        let start = u32::from(range.start());
        let end = u32::from(range.end());

        // Refactored to return the ops array directly to avoid `mut` closure warnings
        let parse_op = || -> Result<Vec<MigrationOp>> {
            let mut local_ops = Vec::new();

            // 1. Whitelist Safe Statements
            if ast::Begin::cast(syntax.clone()).is_some() {
                local_ops.push(MigrationOp::Ignored("BEGIN".into()));
                return Ok(local_ops);
            }
            if ast::Commit::cast(syntax.clone()).is_some() {
                local_ops.push(MigrationOp::Ignored("COMMIT".into()));
                return Ok(local_ops);
            }
            if ast::Analyze::cast(syntax.clone()).is_some() {
                local_ops.push(MigrationOp::Ignored("ANALYZE".into()));
                return Ok(local_ops);
            }
            if ast::Set::cast(syntax.clone()).is_some() {
                local_ops.push(MigrationOp::Ignored("SET".into()));
                return Ok(local_ops);
            }

            // FIX: Safely bypass DML (Data Migrations) using the exact AST structs
            if ast::Insert::cast(syntax.clone()).is_some()
                || ast::Update::cast(syntax.clone()).is_some()
                || ast::Delete::cast(syntax.clone()).is_some()
                || ast::Select::cast(syntax.clone()).is_some()
            {
                local_ops.push(MigrationOp::Ignored("DML".into()));
                return Ok(local_ops);
            }

            // 2. Table Operations
            if let Some(drop_table) = ast::DropTable::cast(syntax.clone()) {
                if drop_table.comma_token().is_some() {
                    return Err(SafeMigrateError::Parse("Multi-table DROP TABLE is not safely verified yet. Split into multiple statements.".into()));
                }

                let path = drop_table
                    .path()
                    .ok_or_else(|| SafeMigrateError::Parse("DropTable missing path".into()))?;

                local_ops.push(MigrationOp::DropTable(extract_table_identity(path)?));
                return Ok(local_ops);
            }

            if let Some(create_table) = ast::CreateTable::cast(syntax.clone()) {
                let path = create_table
                    .path()
                    .ok_or_else(|| SafeMigrateError::Parse("CreateTable missing path".into()))?;

                local_ops.push(MigrationOp::CreateTable(extract_table_identity(path)?));
                return Ok(local_ops);
            }

            // 3. Index Operations
            if let Some(drop_index) = ast::DropIndex::cast(syntax.clone()) {
                let concurrently = drop_index.concurrently_token().is_some();
                let mut indexes = Vec::new();
                for path in drop_index.paths() {
                    indexes.push(extract_index_identity(path)?);
                }
                if indexes.is_empty() {
                    return Err(SafeMigrateError::Parse("DropIndex missing paths".into()));
                }
                local_ops.push(MigrationOp::DropIndex {
                    indexes,
                    concurrently,
                });
                return Ok(local_ops);
            }

            if let Some(create_index) = ast::CreateIndex::cast(syntax.clone()) {
                let table_path = create_index
                    .relation_name()
                    .and_then(|rel| rel.path())
                    .ok_or_else(|| {
                        SafeMigrateError::Parse("CreateIndex missing target table".into())
                    })?;

                let index_name = create_index
                    .name()
                    .and_then(|n| n.ident_token().map(|t| normalize_ident(t.text())));

                local_ops.push(MigrationOp::CreateIndex {
                    index_name,
                    table: extract_table_identity(table_path)?,
                    concurrently: create_index.concurrently_token().is_some(),
                });
                return Ok(local_ops);
            }

            // 4. Alter Table
            if let Some(alter_table) = ast::AlterTable::cast(syntax.clone()) {
                let path = alter_table
                    .relation_name()
                    .and_then(|rel| rel.path())
                    .ok_or_else(|| {
                        SafeMigrateError::Parse("AlterTable missing relation name".into())
                    })?;

                local_ops.push(MigrationOp::AlterTable {
                    table: extract_table_identity(path)?,
                    actions: extract_alter_actions(&alter_table),
                });
                return Ok(local_ops);
            }

            Err(SafeMigrateError::Parse(
                "Statement type not explicitly supported".into(),
            ))
        };

        match parse_op() {
            Ok(parsed_ops) => {
                for op in parsed_ops {
                    ops.push(SpannedOp { op, start, end });
                }
            }
            Err(e) => {
                ops.push(SpannedOp {
                    op: MigrationOp::Unknown {
                        raw: syntax.text().to_string(),
                        reason: e.to_string(),
                    },
                    start,
                    end,
                });
            }
        }
    }

    Ok(ops)
}
