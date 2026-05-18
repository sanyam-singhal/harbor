//! SQLite-backed Harbor store setup.

use core::fmt;
use std::str::FromStr;
use std::time::Duration;

use harbor_core::{StoreError, StoreErrorCode};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::migrations::run_sqlite_migrations;

/// SQLite connection options for Harbor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteStoreOptions {
    max_connections: u32,
    busy_timeout: Duration,
    create_if_missing: bool,
    use_wal: bool,
}

impl SqliteStoreOptions {
    /// Creates SQLite store options.
    #[must_use]
    pub const fn new(
        max_connections: u32,
        busy_timeout: Duration,
        create_if_missing: bool,
        use_wal: bool,
    ) -> Self {
        Self {
            max_connections,
            busy_timeout,
            create_if_missing,
            use_wal,
        }
    }

    /// Options for in-memory SQLite tests.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self {
            max_connections: 1,
            busy_timeout: Duration::from_secs(5),
            create_if_missing: true,
            use_wal: false,
        }
    }

    /// Maximum number of pooled connections.
    #[must_use]
    pub const fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// SQLite busy timeout.
    #[must_use]
    pub const fn busy_timeout(&self) -> Duration {
        self.busy_timeout
    }

    /// Whether SQLx should create a missing database file.
    #[must_use]
    pub const fn create_if_missing(&self) -> bool {
        self.create_if_missing
    }

    /// Whether to request WAL journal mode.
    #[must_use]
    pub const fn use_wal(&self) -> bool {
        self.use_wal
    }
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self {
            max_connections: 5,
            busy_timeout: Duration::from_secs(5),
            create_if_missing: true,
            use_wal: true,
        }
    }
}

/// SQLx-backed SQLite implementation of Harbor storage.
#[derive(Clone)]
pub struct SqliteAuthStore {
    pool: SqlitePool,
}

impl SqliteAuthStore {
    /// Wraps an existing SQLite pool.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Opens a SQLite store from a database URL.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the URL is invalid or SQLx cannot open the
    /// pool.
    pub async fn connect(
        database_url: &str,
        options: SqliteStoreOptions,
    ) -> Result<Self, StoreError> {
        let mut connect_options = SqliteConnectOptions::from_str(database_url)
            .map_err(|_error| StoreError::with_detail(StoreErrorCode::Unavailable, "sqlite_url"))?;
        connect_options = connect_options
            .foreign_keys(true)
            .create_if_missing(options.create_if_missing())
            .busy_timeout(options.busy_timeout());
        if options.use_wal() {
            connect_options = connect_options.journal_mode(SqliteJournalMode::Wal);
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(options.max_connections())
            .connect_with(connect_options)
            .await
            .map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::Unavailable, "sqlite_connect")
            })?;

        Ok(Self::new(pool))
    }

    /// Opens a SQLite store and applies migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when opening the pool or applying migrations
    /// fails.
    pub async fn connect_and_migrate(
        database_url: &str,
        options: SqliteStoreOptions,
    ) -> Result<Self, StoreError> {
        let store = Self::connect(database_url, options).await?;
        store.migrate().await?;
        Ok(store)
    }

    /// Applies Harbor SQLite migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLx cannot apply migrations.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        run_sqlite_migrations(&self.pool).await.map_err(|_error| {
            StoreError::with_detail(StoreErrorCode::Unavailable, "sqlite_migrate")
        })
    }

    /// Returns the underlying SQLx pool.
    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Enables SQLite foreign keys for the current connection and checks the
    /// setting. This is mostly useful for tests around externally provided
    /// pools.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite rejects the PRAGMA statements.
    pub async fn verify_foreign_keys(&self) -> Result<(), StoreError> {
        let enabled: (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(&self.pool)
            .await
            .map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::Unavailable, "sqlite_pragma")
            })?;
        if enabled.0 == 1 {
            Ok(())
        } else {
            Err(StoreError::with_detail(
                StoreErrorCode::Unavailable,
                "sqlite_foreign_keys_disabled",
            ))
        }
    }
}

impl fmt::Debug for SqliteAuthStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteAuthStore { pool: [REDACTED] }")
    }
}

#[cfg(test)]
mod tests {
    use super::{SqliteAuthStore, SqliteStoreOptions};

    #[tokio::test(flavor = "current_thread")]
    async fn connects_migrates_and_checks_foreign_keys() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuthStore::connect_and_migrate(
            "sqlite::memory:",
            SqliteStoreOptions::in_memory(),
        )
        .await?;

        store.verify_foreign_keys().await?;
        assert_eq!(format!("{store:?}"), "SqliteAuthStore { pool: [REDACTED] }");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wraps_existing_pool() -> Result<(), Box<dyn std::error::Error>> {
        let store =
            SqliteAuthStore::connect("sqlite::memory:", SqliteStoreOptions::in_memory()).await?;

        sqlx::query("SELECT 1").execute(store.pool()).await?;
        Ok(())
    }
}
