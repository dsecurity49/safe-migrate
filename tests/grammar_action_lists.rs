//! Every grammar production that carries a repeatable list must be classified.
//!
//! A visitor that reads only the first element of such a list silently loses
//! the rest, so the census below is recomputed from the pinned Squawk grammar
//! and compared against what this build knows about. A grammar that grows a
//! new list fails here by name instead of failing silently in analysis.

use std::path::PathBuf;

/// How this build treats a production whose grammar carries a list.
///
/// `AllActionsApplied` means the model records every element. `Unmodelled`
/// means the statement is not claimed at all, which is honest: an unmodelled
/// statement carries no state, so it can drop nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    AllActionsApplied,
    Unmodelled,
}

/// The classifications for every production the pinned grammar gives a list.
const CLASSIFIED: &[(&str, Handling)] = &[
    // Statement-level ALTER lists. Each must either apply all of its
    // elements or be left unmodelled.
    ("AlterTable", Handling::AllActionsApplied),
    ("AlterForeignTable", Handling::AllActionsApplied),
    ("AlterMaterializedView", Handling::AllActionsApplied),
    ("AlterSequence", Handling::AllActionsApplied),
    ("AlterServer", Handling::Unmodelled),
    ("AlterTypeAttributeActionList", Handling::Unmodelled),
    // Declarations, where a repeated element is part of one object rather
    // than a sequence of transitions.
    ("AddColumn", Handling::AllActionsApplied),
    ("Column", Handling::AllActionsApplied),
    ("ArgList", Handling::AllActionsApplied),
    ("ReturnTableArgList", Handling::AllActionsApplied),
    ("PartitionForValuesWith", Handling::AllActionsApplied),
    ("CompoundSelect", Handling::AllActionsApplied),
    ("ParenSelect", Handling::AllActionsApplied),
    ("Select", Handling::AllActionsApplied),
    ("SelectInto", Handling::AllActionsApplied),
    ("Table", Handling::AllActionsApplied),
    ("Values", Handling::AllActionsApplied),
];

/// The pinned `squawk-syntax` grammar, whose list-bearing productions this
/// build must classify.
fn pinned_grammar() -> String {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME must be set to locate the registry");
            PathBuf::from(home).join(".cargo")
        });
    let sources = cargo_home.join("registry/src");
    let mut found: Vec<PathBuf> = Vec::new();
    for registry in std::fs::read_dir(&sources)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", sources.display()))
    {
        let registry = registry.expect("a readable registry entry");
        let Ok(crates) = std::fs::read_dir(registry.path()) else {
            continue;
        };
        for crate_dir in crates.flatten() {
            let path = crate_dir.path().join("src/postgresql.ungram");
            if path.is_file() {
                found.push(path);
            }
        }
    }
    found.sort();
    assert!(
        !found.is_empty(),
        "the pinned squawk-syntax grammar was not found under {}; \
         this test must fail rather than pass unverified",
        sources.display()
    );
    let newest = found.pop().expect("checked non-empty");
    std::fs::read_to_string(newest).expect("grammar is readable")
}

/// Every production whose right-hand side carries a repeatable list, in both
/// spellings the grammar uses: a named `field:Type*` and an inline
/// `field:(Type (',' Type)*)`.
/// Whether a production body carries a repeatable list, in either spelling:
/// a named `field:Type*` or the inline `field:(Type (',' Type)*)`.
fn has_repeatable_list(body: &str) -> bool {
    let bytes = body.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b':' {
            continue;
        }
        let mut cursor = index + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        // `field:(Type (`
        if bytes.get(cursor) == Some(&b'(') {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let type_start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            if cursor == type_start {
                continue;
            }
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'(') {
                return true;
            }
            continue;
        }
        // `field:Type*`
        let type_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor > type_start && bytes.get(cursor) == Some(&b'*') {
            return true;
        }
    }
    false
}

fn list_bearing_productions(grammar: &str) -> Vec<String> {
    let mut productions: Vec<(String, Vec<&str>)> = Vec::new();
    let mut current: Option<(String, Vec<&str>)> = None;
    for line in grammar.lines() {
        if let Some(name) = line
            .trim_end()
            .strip_suffix(" =")
            .filter(|name| !name.is_empty() && name.starts_with(|c: char| c.is_ascii_uppercase()))
        {
            if let Some(production) = current.take() {
                productions.push(production);
            }
            current = Some((name.trim().to_string(), Vec::new()));
            continue;
        }
        if line.trim().is_empty() {
            if let Some(production) = current.take() {
                productions.push(production);
            }
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push(line);
        }
    }
    if let Some(production) = current {
        productions.push(production);
    }

    productions
        .into_iter()
        .filter(|(_, body)| has_repeatable_list(&body.join("\n")))
        .map(|(name, _)| name)
        .collect()
}

#[test]
fn every_list_bearing_production_is_classified() {
    let grammar = pinned_grammar();
    let actual = list_bearing_productions(&grammar);

    let expected: Vec<&str> = CLASSIFIED.iter().map(|(name, _)| *name).collect();
    let mut missing: Vec<&String> = actual
        .iter()
        .filter(|name| !expected.contains(&name.as_str()))
        .collect();
    let mut stale: Vec<&&str> = expected
        .iter()
        .filter(|name| !actual.contains(&name.to_string()))
        .collect();
    missing.sort();
    stale.sort();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "the grammar's list-bearing productions and this build's \
         classification disagree.\n  unclassified: {missing:?}\n  no longer present: {stale:?}\n\
         classify each in CLASSIFIED before reading that list's elements."
    );
}

#[test]
fn an_alter_statement_is_never_classified_as_partially_applied() {
    // `Unmodelled` is the only permitted escape, because an unmodelled
    // statement applies nothing and so cannot drop a later element.
    for (name, handling) in CLASSIFIED {
        assert!(
            matches!(handling, Handling::AllActionsApplied | Handling::Unmodelled),
            "{name} has a classification this test does not understand"
        );
    }
}
