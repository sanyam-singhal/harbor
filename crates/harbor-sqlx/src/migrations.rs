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

#[cfg(test)]
mod tests {
    use sqlx::{Row, sqlite::SqlitePoolOptions};

    use super::run_sqlite_migrations;

    #[tokio::test(flavor = "current_thread")]
    async fn sqlite_migrations_apply_to_memory_database() -> Result<(), Box<dyn std::error::Error>>
    {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        run_sqlite_migrations(&pool).await?;

        let row = sqlx::query("SELECT COUNT(*) AS count FROM harbor_users")
            .fetch_one(&pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        assert_eq!(count, 0);

        Ok(())
    }
}
