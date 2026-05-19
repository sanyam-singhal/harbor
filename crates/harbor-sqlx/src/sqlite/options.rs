//! SQLite store configuration.

use std::time::Duration;

use harbor_core::{StoreError, StoreErrorCode};

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

    pub(in crate::sqlite) fn validate(&self) -> Result<(), StoreError> {
        if self.max_connections == 0 {
            return Err(StoreError::with_detail(
                StoreErrorCode::Unavailable,
                "sqlite_max_connections",
            ));
        }
        Ok(())
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
