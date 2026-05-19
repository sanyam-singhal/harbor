//! SQLx migration helpers.

use std::path::Path;

use sqlx::{SqlitePool, migrate::MigrateError};

/// Runs Harbor's SQLite migrations against `pool`.
///
/// # Errors
///
/// Returns [`MigrateError`] if SQLx cannot apply the embedded migrations.
pub async fn run_sqlite_migrations(pool: &SqlitePool) -> Result<(), MigrateError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite");
    let migrator = sqlx::migrate::Migrator::new(path).await?;
    migrator.run(pool).await
}
