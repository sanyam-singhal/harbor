//! Migration integration tests.

use harbor_sqlx::migrations::run_sqlite_migrations;
use sqlx::{Row, sqlite::SqlitePoolOptions};

#[tokio::test(flavor = "current_thread")]
async fn sqlite_migrations_apply_to_memory_database() -> Result<(), Box<dyn std::error::Error>> {
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
