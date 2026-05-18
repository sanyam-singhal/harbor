//! SQLite-backed Harbor store setup.

use core::fmt;
use core::future::Future;
use std::str::FromStr;
use std::time::Duration;

use harbor_core::{
    CanonicalEmail, CreateUserEmailInput, CreateUserInput, DomainError, FindEmailByCanonicalInput,
    GetPasswordCredentialInput, GetUserInput, InsertPasswordInput, MarkEmailVerifiedInput,
    PasswordCredentialRecord, PasswordCredentialStore, StoreError, StoreErrorCode,
    UnixTimestampMicros, UserEmailRecord, UserEmailStore, UserId, UserRecord, UserStore,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

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

impl UserStore for SqliteAuthStore {
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> impl Future<Output = Result<UserRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_users \
                 (id, created_at_unix_micros, updated_at_unix_micros, disabled_at_unix_micros) \
                 VALUES (?1, ?2, ?3, NULL)",
            )
            .bind(input.id.as_str())
            .bind(input.now.as_i64())
            .bind(input.now.as_i64())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "create_user"))?;

            Ok(UserRecord {
                id: input.id,
                created_at: input.now,
                updated_at: input.now,
                disabled_at: None,
            })
        }
    }

    fn get_user(
        &self,
        input: GetUserInput,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let row = sqlx::query(
                "SELECT id, created_at_unix_micros, updated_at_unix_micros, \
                 disabled_at_unix_micros FROM harbor_users WHERE id = ?1",
            )
            .bind(input.user_id.as_str())
            .fetch_optional(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "get_user"))?;

            row.map(|row| user_from_row(&row)).transpose()
        }
    }
}

impl UserEmailStore for SqliteAuthStore {
    fn create_user_email(
        &self,
        input: CreateUserEmailInput,
    ) -> impl Future<Output = Result<UserEmailRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_user_emails \
                 (id, user_id, email_original, email_canonical, verified_at_unix_micros, \
                  is_primary, created_at_unix_micros, updated_at_unix_micros) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
            )
            .bind(input.id.as_str())
            .bind(input.user_id.as_str())
            .bind(&input.email_original)
            .bind(input.email_canonical.as_str())
            .bind(if input.is_primary { 1_i64 } else { 0_i64 })
            .bind(input.now.as_i64())
            .bind(input.now.as_i64())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "create_user_email"))?;

            Ok(UserEmailRecord {
                id: input.id,
                user_id: input.user_id,
                email_original: input.email_original,
                email_canonical: input.email_canonical,
                verified_at: None,
                is_primary: input.is_primary,
                created_at: input.now,
                updated_at: input.now,
            })
        }
    }

    fn find_email_by_canonical(
        &self,
        input: FindEmailByCanonicalInput,
    ) -> impl Future<Output = Result<Option<UserEmailRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { find_email_by_canonical(&pool, input.email_canonical).await }
    }

    fn mark_email_verified(
        &self,
        input: MarkEmailVerifiedInput,
    ) -> impl Future<Output = Result<Option<UserEmailRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "UPDATE harbor_user_emails \
                 SET verified_at_unix_micros = ?1, updated_at_unix_micros = ?1 \
                 WHERE email_canonical = ?2",
            )
            .bind(input.verified_at.as_i64())
            .bind(input.email_canonical.as_str())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "mark_email_verified"))?;

            find_email_by_canonical(&pool, input.email_canonical).await
        }
    }
}

impl PasswordCredentialStore for SqliteAuthStore {
    fn upsert_password_credential(
        &self,
        input: InsertPasswordInput,
    ) -> impl Future<Output = Result<PasswordCredentialRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_password_credentials \
                 (user_id, password_hash, password_set_at_unix_micros, password_version) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                   password_hash = excluded.password_hash, \
                   password_set_at_unix_micros = excluded.password_set_at_unix_micros, \
                   password_version = excluded.password_version",
            )
            .bind(input.user_id.as_str())
            .bind(input.password_hash.expose_phc())
            .bind(input.password_set_at.as_i64())
            .bind(input.password_version)
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "upsert_password_credential"))?;

            Ok(PasswordCredentialRecord {
                user_id: input.user_id,
                password_hash: input.password_hash,
                password_set_at: input.password_set_at,
                password_version: input.password_version,
            })
        }
    }

    fn get_password_credential(
        &self,
        input: GetPasswordCredentialInput,
    ) -> impl Future<Output = Result<Option<PasswordCredentialRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let row = sqlx::query(
                "SELECT user_id, password_hash, password_set_at_unix_micros, password_version \
                 FROM harbor_password_credentials WHERE user_id = ?1",
            )
            .bind(input.user_id.as_str())
            .fetch_optional(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "get_password_credential"))?;

            row.map(|row| password_from_row(&row)).transpose()
        }
    }
}

async fn find_email_by_canonical(
    pool: &SqlitePool,
    email_canonical: CanonicalEmail,
) -> Result<Option<UserEmailRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, user_id, email_original, email_canonical, verified_at_unix_micros, \
                is_primary, created_at_unix_micros, updated_at_unix_micros \
         FROM harbor_user_emails WHERE email_canonical = ?1",
    )
    .bind(email_canonical.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|error| map_sqlx_error(error, "find_email_by_canonical"))?;

    row.map(|row| email_from_row(&row)).transpose()
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserRecord, StoreError> {
    Ok(UserRecord {
        id: user_id(get_string(row, "id")?)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        updated_at: timestamp(get_i64(row, "updated_at_unix_micros")?)?,
        disabled_at: optional_timestamp(get_optional_i64(row, "disabled_at_unix_micros")?)?,
    })
}

fn email_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserEmailRecord, StoreError> {
    Ok(UserEmailRecord {
        id: harbor_core::UserEmailId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        user_id: user_id(get_string(row, "user_id")?)?,
        email_original: get_string(row, "email_original")?,
        email_canonical: CanonicalEmail::try_new(get_string(row, "email_canonical")?)
            .map_err(map_domain_error)?,
        verified_at: optional_timestamp(get_optional_i64(row, "verified_at_unix_micros")?)?,
        is_primary: get_i64(row, "is_primary")? == 1,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        updated_at: timestamp(get_i64(row, "updated_at_unix_micros")?)?,
    })
}

fn password_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<PasswordCredentialRecord, StoreError> {
    Ok(PasswordCredentialRecord {
        user_id: user_id(get_string(row, "user_id")?)?,
        password_hash: harbor_core::PasswordHashString::try_new(get_string(row, "password_hash")?)
            .map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::CorruptData, "password_hash")
            })?,
        password_set_at: timestamp(get_i64(row, "password_set_at_unix_micros")?)?,
        password_version: get_i64(row, "password_version")?,
    })
}

fn get_string(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<String, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_i64(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<i64, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_i64(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<i64>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn user_id(value: String) -> Result<UserId, StoreError> {
    UserId::try_new(value).map_err(map_domain_error)
}

fn timestamp(value: i64) -> Result<UnixTimestampMicros, StoreError> {
    UnixTimestampMicros::try_new(value).map_err(map_domain_error)
}

fn optional_timestamp(value: Option<i64>) -> Result<Option<UnixTimestampMicros>, StoreError> {
    value.map(timestamp).transpose()
}

fn map_domain_error(_error: DomainError) -> StoreError {
    StoreError::with_detail(StoreErrorCode::CorruptData, "domain_decode")
}

fn map_sqlx_error(error: sqlx::Error, detail: &'static str) -> StoreError {
    match error {
        sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
            StoreError::with_detail(StoreErrorCode::Conflict, detail)
        }
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::ColumnNotFound(_) => {
            StoreError::with_detail(StoreErrorCode::CorruptData, detail)
        }
        _ => StoreError::with_detail(StoreErrorCode::Unavailable, detail),
    }
}

impl fmt::Debug for SqliteAuthStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteAuthStore { pool: [REDACTED] }")
    }
}

#[cfg(test)]
mod tests {
    use harbor_core::{
        AuthEventId, CreateUserEmailInput, CreateUserInput, EmailAddress,
        FindEmailByCanonicalInput, GetPasswordCredentialInput, GetUserInput, InsertPasswordInput,
        MarkEmailVerifiedInput, PasswordCredentialStore, PasswordHashString, StoreErrorCode,
        UnixTimestampMicros, UserEmailId, UserEmailStore, UserId, UserStore,
    };

    use super::{SqliteAuthStore, SqliteStoreOptions};

    const PHC: &str = "$argon2id$v=19$m=32,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$e9Q8Zc8mW2hS9UG+4XH15Q";

    async fn migrated_store() -> Result<SqliteAuthStore, Box<dyn std::error::Error>> {
        Ok(
            SqliteAuthStore::connect_and_migrate(
                "sqlite::memory:",
                SqliteStoreOptions::in_memory(),
            )
            .await?,
        )
    }

    fn user_id() -> Result<UserId, harbor_core::DomainError> {
        UserId::try_new("user000000000001")
    }

    fn email_id() -> Result<UserEmailId, harbor_core::DomainError> {
        UserEmailId::try_new("email00000000001")
    }

    fn now() -> UnixTimestampMicros {
        UnixTimestampMicros::EPOCH
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connects_migrates_and_checks_foreign_keys() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;

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

    #[tokio::test(flavor = "current_thread")]
    async fn creates_and_fetches_user_email() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let email = EmailAddress::parse("User@Example.com")?;

        let user = store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        let stored_user = store
            .get_user(GetUserInput {
                user_id: user_id.clone(),
            })
            .await?;

        assert_eq!(stored_user, Some(user));

        let inserted = store
            .create_user_email(CreateUserEmailInput {
                id: email_id()?,
                user_id: user_id.clone(),
                email_original: email.original().to_owned(),
                email_canonical: email.canonical().clone(),
                is_primary: true,
                now: now(),
            })
            .await?;
        let fetched = store
            .find_email_by_canonical(FindEmailByCanonicalInput {
                email_canonical: email.canonical().clone(),
            })
            .await?;

        assert_eq!(fetched, Some(inserted));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_canonical_email_is_conflict() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let email = EmailAddress::parse("user@example.com")?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        store
            .create_user_email(CreateUserEmailInput {
                id: email_id()?,
                user_id: user_id.clone(),
                email_original: email.original().to_owned(),
                email_canonical: email.canonical().clone(),
                is_primary: true,
                now: now(),
            })
            .await?;

        let duplicate = store
            .create_user_email(CreateUserEmailInput {
                id: UserEmailId::try_new("email00000000002")?,
                user_id,
                email_original: email.original().to_owned(),
                email_canonical: email.canonical().clone(),
                is_primary: false,
                now: now(),
            })
            .await;

        let error = match duplicate {
            Ok(_) => return Err("duplicate email should fail".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), StoreErrorCode::Conflict);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn marks_email_verified() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let email = EmailAddress::parse("user@example.com")?;
        let verified_at = UnixTimestampMicros::try_new(10)?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        store
            .create_user_email(CreateUserEmailInput {
                id: email_id()?,
                user_id,
                email_original: email.original().to_owned(),
                email_canonical: email.canonical().clone(),
                is_primary: true,
                now: now(),
            })
            .await?;

        let verified = store
            .mark_email_verified(MarkEmailVerifiedInput {
                email_canonical: email.canonical().clone(),
                verified_at,
            })
            .await?;

        let verified = match verified {
            Some(verified) => verified,
            None => return Err("verified email should exist".into()),
        };
        assert_eq!(verified.verified_at, Some(verified_at));
        assert_eq!(verified.updated_at, verified_at);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upserts_and_fetches_password_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;

        let first = store
            .upsert_password_credential(InsertPasswordInput {
                user_id: user_id.clone(),
                password_hash: PasswordHashString::try_new(PHC)?,
                password_set_at: now(),
                password_version: 1,
            })
            .await?;
        let second_time = UnixTimestampMicros::try_new(20)?;
        let second = store
            .upsert_password_credential(InsertPasswordInput {
                user_id: user_id.clone(),
                password_hash: PasswordHashString::try_new(PHC)?,
                password_set_at: second_time,
                password_version: 2,
            })
            .await?;
        let fetched = store
            .get_password_credential(GetPasswordCredentialInput { user_id })
            .await?;

        assert_eq!(first.password_version, 1);
        assert_eq!(second.password_version, 2);
        assert_eq!(fetched, Some(second));
        Ok(())
    }

    #[test]
    fn auth_event_id_is_available_for_later_store_slices() -> Result<(), harbor_core::DomainError> {
        let id = AuthEventId::try_new("event00000000001")?;

        assert_eq!(id.as_str(), "event00000000001");
        Ok(())
    }
}
