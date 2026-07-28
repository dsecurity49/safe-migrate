use safe_migrate::engine::config::Config;
use safe_migrate::engine::engine::SafeMigrateEngine;
use std::collections::HashSet;

fn documented_primary_rule_ids() -> Vec<&'static str> {
    let readme = include_str!("../README.md");
    let catalog = readme
        .split_once("## Rule catalog")
        .and_then(|(_, rest)| rest.split_once("The `blocking-constraint` rule"))
        .map(|(catalog, _)| catalog)
        .expect("README must contain the primary rule catalog");

    catalog
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("| `")
                .and_then(|row| row.split_once('`'))
                .map(|(rule_id, _)| rule_id)
        })
        .collect()
}

#[test]
fn readme_primary_rule_catalog_matches_the_engine() {
    let documented = documented_primary_rule_ids();
    let engine = SafeMigrateEngine::new(Config::default());
    let engine_ids = engine.primary_rule_ids();

    let documented_unique: HashSet<_> = documented.iter().copied().collect();
    assert_eq!(
        documented_unique.len(),
        documented.len(),
        "README primary rule catalog must not contain duplicate IDs"
    );
    assert_eq!(
        documented, engine_ids,
        "README primary rule catalog must match the engine's canonical rule IDs"
    );
}
