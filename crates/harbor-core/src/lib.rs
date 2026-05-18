//! Core domain types and service contracts for Harbor.
//!
//! This crate intentionally has no web framework, database, or email provider
//! dependency. It owns the invariants that all Harbor integrations must obey.

/// Version of the `harbor-core` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
