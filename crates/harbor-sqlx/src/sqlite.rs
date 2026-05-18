//! SQLite-backed Harbor store setup.

use core::fmt;
use core::future::Future;
use std::str::FromStr;
use std::time::Duration;

use harbor_core::{
    AppendAuthEventInput, AuthEventKind, AuthEventRecord, AuthEventStore, CanonicalEmail,
    ChallengeDelivery, ChallengeId, ChallengePurpose, ChallengeRecord, ChallengeStore,
    CreateChallengeInput, CreateSessionInput, CreateUserEmailInput, CreateUserInput,
    DeleteExpiredSessionsInput, DomainError, FindEmailByCanonicalInput, GetChallengeInput,
    GetPasswordCredentialInput, GetSessionInput, GetUserInput, IncrementChallengeAttemptsInput,
    IncrementRateLimitInput, InsertPasswordInput, MarkEmailVerifiedInput, PasswordCredentialRecord,
    PasswordCredentialStore, RateLimitDecision, RateLimitStore, RedirectPath, RetryBudget,
    RevokeSessionInput, RevokeUserSessionsInput, SessionId, SessionRecord, SessionStore,
    StoreError, StoreErrorCode, TokenHash, UnixTimestampMicros, UpdateSessionLastSeenInput,
    UserEmailRecord, UserEmailStore, UserId, UserRecord, UserStore,
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

impl ChallengeStore for SqliteAuthStore {
    fn create_challenge(
        &self,
        input: CreateChallengeInput,
    ) -> impl Future<Output = Result<ChallengeRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_challenges \
                 (id, purpose, user_id, email_canonical, secret_hash, delivery, redirect_path, \
                  expires_at_unix_micros, consumed_at_unix_micros, attempt_count, max_attempts, \
                  resend_after_unix_micros, created_at_unix_micros, last_sent_at_unix_micros) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0, ?9, ?10, ?11, NULL)",
            )
            .bind(input.id.as_str())
            .bind(challenge_purpose_to_db(input.purpose))
            .bind(input.user_id.as_ref().map(UserId::as_str))
            .bind(input.email_canonical.as_str())
            .bind(input.secret_hash.as_bytes())
            .bind(challenge_delivery_to_db(input.delivery))
            .bind(input.redirect_path.as_ref().map(RedirectPath::as_str))
            .bind(input.expires_at.as_i64())
            .bind(i64::try_from(input.max_attempts.get()).map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::CorruptData, "max_attempts")
            })?)
            .bind(input.resend_after.as_i64())
            .bind(input.now.as_i64())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "create_challenge"))?;

            Ok(ChallengeRecord {
                id: input.id,
                purpose: input.purpose,
                user_id: input.user_id,
                email_canonical: input.email_canonical,
                secret_hash: input.secret_hash,
                delivery: input.delivery,
                redirect_path: input.redirect_path,
                expires_at: input.expires_at,
                consumed_at: None,
                attempt_count: 0,
                max_attempts: input.max_attempts,
                resend_after: input.resend_after,
                created_at: input.now,
                last_sent_at: None,
            })
        }
    }

    fn get_challenge(
        &self,
        input: GetChallengeInput,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { get_challenge_by_id(&pool, input.challenge_id).await }
    }

    fn increment_challenge_attempts(
        &self,
        input: IncrementChallengeAttemptsInput,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "UPDATE harbor_challenges SET attempt_count = attempt_count + 1 WHERE id = ?1",
            )
            .bind(input.challenge_id.as_str())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "increment_challenge_attempts"))?;

            get_challenge_by_id(&pool, input.challenge_id).await
        }
    }

    fn consume_challenge(
        &self,
        input: GetChallengeInput,
        consumed_at: UnixTimestampMicros,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let result = sqlx::query(
                "UPDATE harbor_challenges SET consumed_at_unix_micros = ?1 \
                 WHERE id = ?2 AND consumed_at_unix_micros IS NULL",
            )
            .bind(consumed_at.as_i64())
            .bind(input.challenge_id.as_str())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "consume_challenge"))?;

            if result.rows_affected() == 0 {
                Ok(None)
            } else {
                get_challenge_by_id(&pool, input.challenge_id).await
            }
        }
    }
}

impl SessionStore for SqliteAuthStore {
    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> impl Future<Output = Result<SessionRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_sessions \
                 (id, user_id, token_hash, created_at_unix_micros, last_seen_at_unix_micros, \
                  idle_expires_at_unix_micros, absolute_expires_at_unix_micros, \
                  revoked_at_unix_micros, ip_hash, user_agent_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, NULL, ?7, ?8)",
            )
            .bind(input.id.as_str())
            .bind(input.user_id.as_str())
            .bind(input.token_hash.as_bytes())
            .bind(input.created_at.as_i64())
            .bind(input.idle_expires_at.as_i64())
            .bind(input.absolute_expires_at.as_i64())
            .bind(input.ip_hash.as_ref().map(TokenHash::as_bytes))
            .bind(input.user_agent_hash.as_ref().map(TokenHash::as_bytes))
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "create_session"))?;

            Ok(SessionRecord {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                created_at: input.created_at,
                last_seen_at: input.created_at,
                idle_expires_at: input.idle_expires_at,
                absolute_expires_at: input.absolute_expires_at,
                revoked_at: None,
                ip_hash: input.ip_hash,
                user_agent_hash: input.user_agent_hash,
            })
        }
    }

    fn get_session_by_token_hash(
        &self,
        input: GetSessionInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { get_session_by_token_hash(&pool, input.token_hash).await }
    }

    fn update_session_last_seen(
        &self,
        input: UpdateSessionLastSeenInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query("UPDATE harbor_sessions SET last_seen_at_unix_micros = ?1 WHERE id = ?2")
                .bind(input.last_seen_at.as_i64())
                .bind(input.session_id.as_str())
                .execute(&pool)
                .await
                .map_err(|error| map_sqlx_error(error, "update_session_last_seen"))?;

            get_session_by_id(&pool, input.session_id).await
        }
    }

    fn revoke_session(
        &self,
        input: RevokeSessionInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query("UPDATE harbor_sessions SET revoked_at_unix_micros = ?1 WHERE id = ?2")
                .bind(input.revoked_at.as_i64())
                .bind(input.session_id.as_str())
                .execute(&pool)
                .await
                .map_err(|error| map_sqlx_error(error, "revoke_session"))?;

            get_session_by_id(&pool, input.session_id).await
        }
    }

    fn revoke_user_sessions(
        &self,
        input: RevokeUserSessionsInput,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let result = sqlx::query(
                "UPDATE harbor_sessions SET revoked_at_unix_micros = ?1 \
                 WHERE user_id = ?2 AND revoked_at_unix_micros IS NULL",
            )
            .bind(input.revoked_at.as_i64())
            .bind(input.user_id.as_str())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "revoke_user_sessions"))?;

            Ok(result.rows_affected())
        }
    }

    fn delete_expired_sessions(
        &self,
        input: DeleteExpiredSessionsInput,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let result = sqlx::query(
                "DELETE FROM harbor_sessions \
                 WHERE revoked_at_unix_micros IS NOT NULL \
                    OR idle_expires_at_unix_micros <= ?1 \
                    OR absolute_expires_at_unix_micros <= ?1",
            )
            .bind(input.now.as_i64())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "delete_expired_sessions"))?;

            Ok(result.rows_affected())
        }
    }
}

impl RateLimitStore for SqliteAuthStore {
    fn increment_rate_limit(
        &self,
        input: IncrementRateLimitInput,
    ) -> impl Future<Output = Result<RateLimitDecision, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let row = sqlx::query(
                "INSERT INTO harbor_rate_limits (scope, key_hash, window_start_unix_micros, count) \
                 VALUES (?1, ?2, ?3, 1) \
                 ON CONFLICT(scope, key_hash, window_start_unix_micros) DO UPDATE SET \
                   count = count + 1 \
                 RETURNING count",
            )
            .bind(&input.scope)
            .bind(input.key_hash.as_bytes())
            .bind(input.window_start.as_i64())
            .fetch_one(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "increment_rate_limit"))?;
            let count = usize::try_from(get_i64(&row, "count")?).map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::CorruptData, "rate_limit_count")
            })?;

            Ok(RateLimitDecision {
                count,
                allowed: count <= input.max_count.get(),
            })
        }
    }
}

impl AuthEventStore for SqliteAuthStore {
    fn append_auth_event(
        &self,
        input: AppendAuthEventInput,
    ) -> impl Future<Output = Result<AuthEventRecord, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO harbor_auth_events \
                 (id, user_id, email_canonical, kind, occurred_at_unix_micros, \
                  ip_hash, user_agent_hash, detail_code) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(input.id.as_str())
            .bind(input.user_id.as_ref().map(UserId::as_str))
            .bind(input.email_canonical.as_ref().map(CanonicalEmail::as_str))
            .bind(auth_event_kind_to_db(input.kind))
            .bind(input.occurred_at.as_i64())
            .bind(input.ip_hash.as_ref().map(TokenHash::as_bytes))
            .bind(input.user_agent_hash.as_ref().map(TokenHash::as_bytes))
            .bind(input.detail_code.as_deref())
            .execute(&pool)
            .await
            .map_err(|error| map_sqlx_error(error, "append_auth_event"))?;

            Ok(AuthEventRecord {
                id: input.id,
                user_id: input.user_id,
                email_canonical: input.email_canonical,
                kind: input.kind,
                occurred_at: input.occurred_at,
                ip_hash: input.ip_hash,
                user_agent_hash: input.user_agent_hash,
                detail_code: input.detail_code,
            })
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

async fn get_challenge_by_id(
    pool: &SqlitePool,
    challenge_id: ChallengeId,
) -> Result<Option<ChallengeRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, purpose, user_id, email_canonical, secret_hash, delivery, redirect_path, \
                expires_at_unix_micros, consumed_at_unix_micros, attempt_count, max_attempts, \
                resend_after_unix_micros, created_at_unix_micros, last_sent_at_unix_micros \
         FROM harbor_challenges WHERE id = ?1",
    )
    .bind(challenge_id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|error| map_sqlx_error(error, "get_challenge"))?;

    row.map(|row| challenge_from_row(&row)).transpose()
}

fn challenge_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ChallengeRecord, StoreError> {
    Ok(ChallengeRecord {
        id: ChallengeId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        purpose: challenge_purpose_from_db(&get_string(row, "purpose")?)?,
        user_id: get_optional_string(row, "user_id")?
            .map(user_id)
            .transpose()?,
        email_canonical: CanonicalEmail::try_new(get_string(row, "email_canonical")?)
            .map_err(map_domain_error)?,
        secret_hash: TokenHash::try_new(get_bytes(row, "secret_hash")?)
            .map_err(map_domain_error)?,
        delivery: challenge_delivery_from_db(&get_string(row, "delivery")?)?,
        redirect_path: get_optional_string(row, "redirect_path")?
            .map(RedirectPath::try_new)
            .transpose()
            .map_err(map_domain_error)?,
        expires_at: timestamp(get_i64(row, "expires_at_unix_micros")?)?,
        consumed_at: optional_timestamp(get_optional_i64(row, "consumed_at_unix_micros")?)?,
        attempt_count: get_i64(row, "attempt_count")?,
        max_attempts: retry_budget(get_i64(row, "max_attempts")?)?,
        resend_after: timestamp(get_i64(row, "resend_after_unix_micros")?)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        last_sent_at: optional_timestamp(get_optional_i64(row, "last_sent_at_unix_micros")?)?,
    })
}

async fn get_session_by_token_hash(
    pool: &SqlitePool,
    token_hash: TokenHash,
) -> Result<Option<SessionRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, user_id, token_hash, created_at_unix_micros, last_seen_at_unix_micros, \
                idle_expires_at_unix_micros, absolute_expires_at_unix_micros, \
                revoked_at_unix_micros, ip_hash, user_agent_hash \
         FROM harbor_sessions WHERE token_hash = ?1",
    )
    .bind(token_hash.as_bytes())
    .fetch_optional(pool)
    .await
    .map_err(|error| map_sqlx_error(error, "get_session_by_token_hash"))?;

    row.map(|row| session_from_row(&row)).transpose()
}

async fn get_session_by_id(
    pool: &SqlitePool,
    session_id: SessionId,
) -> Result<Option<SessionRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, user_id, token_hash, created_at_unix_micros, last_seen_at_unix_micros, \
                idle_expires_at_unix_micros, absolute_expires_at_unix_micros, \
                revoked_at_unix_micros, ip_hash, user_agent_hash \
         FROM harbor_sessions WHERE id = ?1",
    )
    .bind(session_id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|error| map_sqlx_error(error, "get_session_by_id"))?;

    row.map(|row| session_from_row(&row)).transpose()
}

fn session_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRecord, StoreError> {
    Ok(SessionRecord {
        id: SessionId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        user_id: user_id(get_string(row, "user_id")?)?,
        token_hash: TokenHash::try_new(get_bytes(row, "token_hash")?).map_err(map_domain_error)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        last_seen_at: timestamp(get_i64(row, "last_seen_at_unix_micros")?)?,
        idle_expires_at: timestamp(get_i64(row, "idle_expires_at_unix_micros")?)?,
        absolute_expires_at: timestamp(get_i64(row, "absolute_expires_at_unix_micros")?)?,
        revoked_at: optional_timestamp(get_optional_i64(row, "revoked_at_unix_micros")?)?,
        ip_hash: get_optional_bytes(row, "ip_hash")?
            .map(TokenHash::try_new)
            .transpose()
            .map_err(map_domain_error)?,
        user_agent_hash: get_optional_bytes(row, "user_agent_hash")?
            .map(TokenHash::try_new)
            .transpose()
            .map_err(map_domain_error)?,
    })
}

fn auth_event_kind_to_db(value: AuthEventKind) -> &'static str {
    match value {
        AuthEventKind::SignupRequested => "signup_requested",
        AuthEventKind::EmailVerified => "email_verified",
        AuthEventKind::SignInSucceeded => "sign_in_succeeded",
        AuthEventKind::SignInFailed => "sign_in_failed",
        AuthEventKind::PasswordResetRequested => "password_reset_requested",
        AuthEventKind::PasswordResetCompleted => "password_reset_completed",
        AuthEventKind::SessionRevoked => "session_revoked",
        _ => "unknown",
    }
}

fn get_string(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<String, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_string(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<String>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_bytes(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<Vec<u8>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_bytes(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<Vec<u8>>, StoreError> {
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

fn retry_budget(value: i64) -> Result<RetryBudget, StoreError> {
    let value = usize::try_from(value)
        .map_err(|_error| StoreError::with_detail(StoreErrorCode::CorruptData, "retry_budget"))?;
    RetryBudget::try_new(value).map_err(map_domain_error)
}

fn challenge_purpose_to_db(value: ChallengePurpose) -> &'static str {
    match value {
        ChallengePurpose::SignupConfirmation => "signup_confirmation",
        ChallengePurpose::EmailSignIn => "email_sign_in",
        ChallengePurpose::PasswordReset => "password_reset",
        _ => "unknown",
    }
}

fn challenge_purpose_from_db(value: &str) -> Result<ChallengePurpose, StoreError> {
    match value {
        "signup_confirmation" => Ok(ChallengePurpose::SignupConfirmation),
        "email_sign_in" => Ok(ChallengePurpose::EmailSignIn),
        "password_reset" => Ok(ChallengePurpose::PasswordReset),
        _ => Err(StoreError::with_detail(
            StoreErrorCode::CorruptData,
            "challenge_purpose",
        )),
    }
}

fn challenge_delivery_to_db(value: ChallengeDelivery) -> &'static str {
    match value {
        ChallengeDelivery::MagicLink => "magic_link",
        ChallengeDelivery::OtpCode => "otp_code",
        ChallengeDelivery::Both => "both",
        _ => "unknown",
    }
}

fn challenge_delivery_from_db(value: &str) -> Result<ChallengeDelivery, StoreError> {
    match value {
        "magic_link" => Ok(ChallengeDelivery::MagicLink),
        "otp_code" => Ok(ChallengeDelivery::OtpCode),
        "both" => Ok(ChallengeDelivery::Both),
        _ => Err(StoreError::with_detail(
            StoreErrorCode::CorruptData,
            "challenge_delivery",
        )),
    }
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
        AppendAuthEventInput, Argon2Params, Argon2PasswordHasher, AuthErrorCode, AuthEventId,
        AuthEventKind, AuthEventStore, AuthService, ChallengeDelivery, ChallengeId,
        ChallengePurpose, ChallengeStore, CreateChallengeInput, CreateSessionInput,
        CreateUserEmailInput, CreateUserInput, DeleteExpiredSessionsInput, EmailAddress,
        FindEmailByCanonicalInput, GetChallengeInput, GetPasswordCredentialInput, GetSessionInput,
        GetUserInput, HmacSecretKey, IncrementChallengeAttemptsInput, IncrementRateLimitInput,
        InsertPasswordInput, MarkEmailVerifiedInput, PasswordCredentialStore, PasswordHashString,
        PasswordPolicy, RateLimitStore, RedirectPath, RetryBudget, RevokeSessionInput,
        RevokeUserSessionsInput, SecretToken, SessionId, SessionStore, StoreErrorCode, TokenHash,
        UnixTimestampMicros, UpdateSessionLastSeenInput, UserEmailId, UserEmailStore, UserId,
        UserStore,
    };
    use harbor_test_support::{DeterministicSecretGenerator, FixedClock};
    use sqlx::Row;

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

    fn challenge_id() -> Result<ChallengeId, harbor_core::DomainError> {
        ChallengeId::try_new("challenge00000001")
    }

    fn token_hash() -> Result<TokenHash, harbor_core::DomainError> {
        TokenHash::try_new(vec![1, 2, 3, 4])
    }

    fn second_token_hash() -> Result<TokenHash, harbor_core::DomainError> {
        TokenHash::try_new(vec![5, 6, 7, 8])
    }

    fn session_id() -> Result<SessionId, harbor_core::DomainError> {
        SessionId::try_new("session000000001")
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

    #[tokio::test(flavor = "current_thread")]
    async fn creates_increments_and_consumes_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let email = EmailAddress::parse("user@example.com")?;
        let expires_at = UnixTimestampMicros::try_new(600_000_000)?;
        let consumed_at = UnixTimestampMicros::try_new(10)?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        let created = store
            .create_challenge(CreateChallengeInput {
                id: challenge_id()?,
                purpose: ChallengePurpose::SignupConfirmation,
                user_id: Some(user_id),
                email_canonical: email.canonical().clone(),
                secret_hash: token_hash()?,
                delivery: ChallengeDelivery::Both,
                redirect_path: Some(RedirectPath::try_new("/account")?),
                expires_at,
                max_attempts: RetryBudget::try_new(5)?,
                resend_after: now(),
                now: now(),
            })
            .await?;

        let fetched = store
            .get_challenge(GetChallengeInput {
                challenge_id: created.id.clone(),
            })
            .await?;
        assert_eq!(fetched, Some(created.clone()));

        let incremented = store
            .increment_challenge_attempts(IncrementChallengeAttemptsInput {
                challenge_id: created.id.clone(),
            })
            .await?;
        let incremented = match incremented {
            Some(challenge) => challenge,
            None => return Err("challenge should exist after increment".into()),
        };
        assert_eq!(incremented.attempt_count, 1);

        let consumed = store
            .consume_challenge(
                GetChallengeInput {
                    challenge_id: created.id.clone(),
                },
                consumed_at,
            )
            .await?;
        let consumed = match consumed {
            Some(challenge) => challenge,
            None => return Err("challenge should be consumed once".into()),
        };
        assert_eq!(consumed.consumed_at, Some(consumed_at));

        let second_consume = store
            .consume_challenge(
                GetChallengeInput {
                    challenge_id: created.id,
                },
                consumed_at,
            )
            .await?;
        assert_eq!(second_consume, None);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn creates_refreshes_revokes_and_deletes_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let session_id = session_id()?;
        let token_hash = token_hash()?;
        let refreshed_at = UnixTimestampMicros::try_new(5)?;
        let idle_expires_at = UnixTimestampMicros::try_new(10)?;
        let absolute_expires_at = UnixTimestampMicros::try_new(20)?;
        let cleanup_at = UnixTimestampMicros::try_new(30)?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        let created = store
            .create_session(CreateSessionInput {
                id: session_id.clone(),
                user_id: user_id.clone(),
                token_hash: token_hash.clone(),
                created_at: now(),
                idle_expires_at,
                absolute_expires_at,
                ip_hash: Some(second_token_hash()?),
                user_agent_hash: None,
            })
            .await?;
        let fetched = store
            .get_session_by_token_hash(GetSessionInput {
                token_hash: token_hash.clone(),
            })
            .await?;
        assert_eq!(fetched, Some(created));

        let refreshed = store
            .update_session_last_seen(UpdateSessionLastSeenInput {
                session_id: session_id.clone(),
                last_seen_at: refreshed_at,
            })
            .await?;
        let refreshed = match refreshed {
            Some(session) => session,
            None => return Err("session should refresh".into()),
        };
        assert_eq!(refreshed.last_seen_at, refreshed_at);

        let revoked = store
            .revoke_session(RevokeSessionInput {
                session_id: session_id.clone(),
                revoked_at: refreshed_at,
            })
            .await?;
        let revoked = match revoked {
            Some(session) => session,
            None => return Err("session should revoke".into()),
        };
        assert_eq!(revoked.revoked_at, Some(refreshed_at));

        let deleted = store
            .delete_expired_sessions(DeleteExpiredSessionsInput { now: cleanup_at })
            .await?;
        assert_eq!(deleted, 1);

        let missing = store
            .get_session_by_token_hash(GetSessionInput { token_hash })
            .await?;
        assert_eq!(missing, None);

        store
            .create_session(CreateSessionInput {
                id: SessionId::try_new("session000000002")?,
                user_id: user_id.clone(),
                token_hash: second_token_hash()?,
                created_at: now(),
                idle_expires_at,
                absolute_expires_at,
                ip_hash: None,
                user_agent_hash: None,
            })
            .await?;
        let revoked_count = store
            .revoke_user_sessions(RevokeUserSessionsInput {
                user_id,
                revoked_at: cleanup_at,
            })
            .await?;
        assert_eq!(revoked_count, 1);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn increments_rate_limits_with_boundary_decision()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let key_hash = token_hash()?;
        let max_count = RetryBudget::try_new(2)?;

        let first = store
            .increment_rate_limit(IncrementRateLimitInput {
                scope: "signin".to_owned(),
                key_hash: key_hash.clone(),
                window_start: now(),
                max_count,
            })
            .await?;
        let second = store
            .increment_rate_limit(IncrementRateLimitInput {
                scope: "signin".to_owned(),
                key_hash: key_hash.clone(),
                window_start: now(),
                max_count,
            })
            .await?;
        let third = store
            .increment_rate_limit(IncrementRateLimitInput {
                scope: "signin".to_owned(),
                key_hash,
                window_start: now(),
                max_count,
            })
            .await?;

        assert_eq!(first.count, 1);
        assert!(first.allowed);
        assert_eq!(second.count, 2);
        assert!(second.allowed);
        assert_eq!(third.count, 3);
        assert!(!third.allowed);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn appends_auth_events_with_hashed_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let user_id = user_id()?;
        let email = EmailAddress::parse("user@example.com")?;
        let ip_hash = token_hash()?;
        let user_agent_hash = second_token_hash()?;

        store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now: now(),
            })
            .await?;
        let event = store
            .append_auth_event(AppendAuthEventInput {
                id: AuthEventId::try_new("event00000000001")?,
                user_id: Some(user_id),
                email_canonical: Some(email.canonical().clone()),
                kind: AuthEventKind::SignInSucceeded,
                occurred_at: now(),
                ip_hash: Some(ip_hash.clone()),
                user_agent_hash: Some(user_agent_hash.clone()),
                detail_code: Some("password".to_owned()),
            })
            .await?;

        let row = sqlx::query(
            "SELECT ip_hash, user_agent_hash, detail_code FROM harbor_auth_events WHERE id = ?1",
        )
        .bind(event.id.as_str())
        .fetch_one(store.pool())
        .await?;
        let stored_ip_hash: Vec<u8> = row.try_get("ip_hash")?;
        let stored_user_agent_hash: Vec<u8> = row.try_get("user_agent_hash")?;
        let detail_code: String = row.try_get("detail_code")?;

        assert_eq!(stored_ip_hash, ip_hash.as_bytes());
        assert_eq!(stored_user_agent_hash, user_agent_hash.as_bytes());
        assert_eq!(detail_code, "password");
        assert_eq!(event.kind, AuthEventKind::SignInSucceeded);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sqlite_store_satisfies_shared_auth_store_contracts()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;

        harbor_test_support::store_contracts::run_auth_store_contracts(store).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn password_service_signup_signin_current_session_and_signout()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let service = AuthService::new(
            store.clone(),
            FixedClock::new(now()),
            DeterministicSecretGenerator::new(),
            HmacSecretKey::try_new(vec![9; 32])?,
            Argon2PasswordHasher::new(
                PasswordPolicy::try_new(8, 128)?,
                Argon2Params::try_new(32, 1, 1)?,
            ),
        );

        let signup = service
            .sign_up_with_password(harbor_core::PasswordSignUpInput {
                email: "service@example.com".to_owned(),
                password: "correct horse battery staple".to_owned(),
            })
            .await?;
        let unverified = service
            .sign_in_with_password(harbor_core::PasswordSignInInput {
                email: "service@example.com".to_owned(),
                password: "correct horse battery staple".to_owned(),
                redirect_path: Some(RedirectPath::try_new("/account")?),
            })
            .await;
        let unverified = match unverified {
            Ok(_) => return Err("unverified signin should fail".into()),
            Err(error) => error,
        };
        assert_eq!(unverified.code(), AuthErrorCode::EmailNotVerified);

        let confirmation = service
            .create_email_challenge(harbor_core::EmailChallengeInput {
                purpose: ChallengePurpose::SignupConfirmation,
                delivery: ChallengeDelivery::MagicLink,
                email: signup.email.email_original.clone(),
                user_id: Some(signup.user.id.clone()),
                redirect_path: Some(RedirectPath::try_new("/account")?),
            })
            .await?;
        let verified = service
            .verify_email_challenge(harbor_core::VerifyChallengeInput {
                challenge_id: confirmation.challenge.id,
                purpose: ChallengePurpose::SignupConfirmation,
                secret: confirmation.secret,
            })
            .await?;
        assert_eq!(
            verified.challenge.email_canonical,
            signup.email.email_canonical
        );

        let signin = service
            .sign_in_with_password(harbor_core::PasswordSignInInput {
                email: "SERVICE@example.com".to_owned(),
                password: "correct horse battery staple".to_owned(),
                redirect_path: Some(RedirectPath::try_new("/account")?),
            })
            .await?;
        assert_eq!(
            signin.redirect_path,
            Some(RedirectPath::try_new("/account")?)
        );

        let current = service.current_session(&signin.session_token).await?;
        assert!(current.is_some());

        let signed_out = service.sign_out(&signin.session_token).await?;
        assert!(signed_out);
        let current_after_signout = service.current_session(&signin.session_token).await?;
        assert_eq!(current_after_signout, None);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn email_challenge_service_rejects_bad_secret_and_consumed_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = migrated_store().await?;
        let service = AuthService::new(
            store.clone(),
            FixedClock::new(now()),
            DeterministicSecretGenerator::new(),
            HmacSecretKey::try_new(vec![9; 32])?,
            Argon2PasswordHasher::new(
                PasswordPolicy::try_new(8, 128)?,
                Argon2Params::try_new(32, 1, 1)?,
            ),
        );

        let challenge = service
            .create_email_challenge(harbor_core::EmailChallengeInput {
                purpose: ChallengePurpose::EmailSignIn,
                delivery: ChallengeDelivery::OtpCode,
                email: "challenge@example.com".to_owned(),
                user_id: None,
                redirect_path: Some(RedirectPath::try_new("/account")?),
            })
            .await?;
        assert_eq!(challenge.secret.expose_secret().len(), 8);
        assert!(
            challenge
                .secret
                .expose_secret()
                .chars()
                .all(|character| character.is_ascii_digit())
        );

        let bad_secret = service
            .verify_email_challenge(harbor_core::VerifyChallengeInput {
                challenge_id: challenge.challenge.id.clone(),
                purpose: ChallengePurpose::EmailSignIn,
                secret: SecretToken::try_new("00000000")?,
            })
            .await;
        let bad_secret = match bad_secret {
            Ok(_) => return Err("wrong challenge secret should fail".into()),
            Err(error) => error,
        };
        assert_eq!(bad_secret.code(), AuthErrorCode::InvalidCredentials);

        let incremented = store
            .get_challenge(GetChallengeInput {
                challenge_id: challenge.challenge.id.clone(),
            })
            .await?;
        let incremented = match incremented {
            Some(challenge) => challenge,
            None => return Err("challenge should remain after failed attempt".into()),
        };
        assert_eq!(incremented.attempt_count, 1);

        let verified = service
            .verify_email_challenge(harbor_core::VerifyChallengeInput {
                challenge_id: challenge.challenge.id.clone(),
                purpose: ChallengePurpose::EmailSignIn,
                secret: challenge.secret,
            })
            .await?;
        assert_eq!(
            verified.challenge.redirect_path,
            Some(RedirectPath::try_new("/account")?)
        );

        let reused = service
            .verify_email_challenge(harbor_core::VerifyChallengeInput {
                challenge_id: challenge.challenge.id,
                purpose: ChallengePurpose::EmailSignIn,
                secret: SecretToken::try_new("00000000")?,
            })
            .await;
        let reused = match reused {
            Ok(_) => return Err("consumed challenge should be single use".into()),
            Err(error) => error,
        };
        assert_eq!(reused.code(), AuthErrorCode::InvalidCredentials);
        Ok(())
    }

    #[test]
    fn auth_event_id_is_available_for_later_store_slices() -> Result<(), harbor_core::DomainError> {
        let id = AuthEventId::try_new("event00000000001")?;

        assert_eq!(id.as_str(), "event00000000001");
        Ok(())
    }
}
