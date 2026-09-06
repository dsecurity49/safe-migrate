//! PostgreSQL migration safety analysis backed by a synchronized catalog baseline.
//!
//! Supported integrations use the [`api`] module. Parser, schema-state, and
//! rule-engine implementation details are intentionally private.
#![warn(missing_docs)]

/// Supported Rust API for configuration, synchronization, and analysis.
pub mod api;

// Lets crate-internal regression modules retain their historical fully
// qualified paths while compiling inside this crate's privacy boundary.
#[cfg(test)]
extern crate self as safe_migrate;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

// The analyzer and catalog model are deliberately private. The supported
// contract is `safe_migrate::api`; keeping this crate-private prevents callers
// from coupling to mutable state-machine implementation details.
pub(crate) mod _internal {
    pub mod analysis;
    pub mod ast;
    pub mod db;
    pub mod engine;
    pub mod model;
    pub mod report;
    pub mod rules;
    pub mod sync;

    #[cfg(test)]
    pub mod sync_tests;
    #[cfg(test)]
    pub(crate) mod test_support;
}

#[cfg(test)]
#[path = "internal_tests.rs"]
mod internal_tests;
