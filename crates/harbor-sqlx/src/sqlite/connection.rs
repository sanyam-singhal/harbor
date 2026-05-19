//! SQLite connection and migration setup.

use std::str::FromStr;

use harbor_core::{StoreError, StoreErrorCode};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::migrations::run_sqlite_migrations;
use crate::sqlite::{SqliteAuthStore, SqliteStoreOptions};

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
        options.validate()?;
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

    /// Checks whether SQLite foreign keys are enabled for the current pool.
    /// This is mostly useful for tests around externally provided pools.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite rejects the PRAGMA statement or
    /// foreign keys are disabled.
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
