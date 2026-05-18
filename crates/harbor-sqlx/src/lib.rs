//! SQLx-backed storage for Harbor.
//!
//! SQLite is implemented first. PostgreSQL and MySQL should be added as
//! separate implementations that pass the same store contract tests.

pub mod migrations;
pub mod sqlite;

/// Version of the `harbor-sqlx` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use sqlite::{SqliteAuthStore, SqliteStoreOptions};
