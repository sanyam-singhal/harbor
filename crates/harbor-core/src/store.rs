//! Storage contracts for Harbor.
//!
//! These traits describe Harbor's persistence boundary without exposing any
//! SQLx types. Implementations are responsible for preserving transaction
//! semantics documented on each method. Service code owns the higher-level auth
//! invariants, while stores own durable reads, writes, uniqueness constraints,
//! and atomic transitions.

use core::future::Future;

use crate::{
    AuthEventId, CanonicalEmail, ChallengeId, PasswordHashString, RedirectPath, RetryBudget,
    SessionId, StoreError, TokenHash, UnixTimestampMicros, UserEmailId, UserId,
};

/// Persisted Harbor user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// Stable user identifier.
    pub id: UserId,
    /// Creation timestamp.
    pub created_at: UnixTimestampMicros,
    /// Last update timestamp.
    pub updated_at: UnixTimestampMicros,
    /// Disable timestamp, if the user is disabled.
    pub disabled_at: Option<UnixTimestampMicros>,
}

/// Persisted user email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEmailRecord {
    /// Stable email row identifier.
    pub id: UserEmailId,
    /// Owning user id.
    pub user_id: UserId,
    /// Original accepted email spelling.
    pub email_original: String,
    /// Canonical lookup email.
    pub email_canonical: CanonicalEmail,
    /// Verification timestamp.
    pub verified_at: Option<UnixTimestampMicros>,
    /// Whether this is the user's primary email.
    pub is_primary: bool,
    /// Creation timestamp.
    pub created_at: UnixTimestampMicros,
    /// Last update timestamp.
    pub updated_at: UnixTimestampMicros,
}

/// Stored password credential.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordCredentialRecord {
    /// Owning user id.
    pub user_id: UserId,
    /// PHC password hash.
    pub password_hash: PasswordHashString,
    /// Timestamp when the password was set.
    pub password_set_at: UnixTimestampMicros,
    /// Application credential version.
    pub password_version: i64,
}

impl core::fmt::Debug for PasswordCredentialRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PasswordCredentialRecord")
            .field("user_id", &self.user_id)
            .field("password_hash", &"[REDACTED]")
            .field("password_set_at", &self.password_set_at)
            .field("password_version", &self.password_version)
            .finish()
    }
}

/// Email challenge purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChallengePurpose {
    /// Confirm a signup email address.
    SignupConfirmation,
    /// Sign in using email possession.
    EmailSignIn,
    /// Reset a password.
    PasswordReset,
}

/// Email challenge delivery style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChallengeDelivery {
    /// High-entropy URL token.
    MagicLink,
    /// Numeric OTP code.
    OtpCode,
}

/// Persisted email challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRecord {
    /// Challenge id.
    pub id: ChallengeId,
    /// Challenge purpose.
    pub purpose: ChallengePurpose,
    /// Optional linked user.
    pub user_id: Option<UserId>,
    /// Canonical target email.
    pub email_canonical: CanonicalEmail,
    /// Hash of the challenge secret.
    pub secret_hash: TokenHash,
    /// Delivery style.
    pub delivery: ChallengeDelivery,
    /// Optional validated redirect path.
    pub redirect_path: Option<RedirectPath>,
    /// Expiry timestamp.
    pub expires_at: UnixTimestampMicros,
    /// Consumption timestamp.
    pub consumed_at: Option<UnixTimestampMicros>,
    /// Failed attempt count.
    pub attempt_count: i64,
    /// Maximum failed attempts before the challenge is exhausted.
    pub max_attempts: RetryBudget,
    /// Earliest timestamp at which the challenge can be resent.
    pub resend_after: UnixTimestampMicros,
    /// Creation timestamp.
    pub created_at: UnixTimestampMicros,
    /// Last delivery timestamp.
    pub last_sent_at: Option<UnixTimestampMicros>,
}

/// Persisted session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session row id.
    pub id: SessionId,
    /// Owning user id.
    pub user_id: UserId,
    /// Hash of the browser token.
    pub token_hash: TokenHash,
    /// Creation timestamp.
    pub created_at: UnixTimestampMicros,
    /// Last seen timestamp.
    pub last_seen_at: UnixTimestampMicros,
    /// Idle expiry timestamp.
    pub idle_expires_at: UnixTimestampMicros,
    /// Absolute expiry timestamp.
    pub absolute_expires_at: UnixTimestampMicros,
    /// Revocation timestamp.
    pub revoked_at: Option<UnixTimestampMicros>,
    /// Hashed IP metadata.
    pub ip_hash: Option<TokenHash>,
    /// Hashed user-agent metadata.
    pub user_agent_hash: Option<TokenHash>,
}

/// Auth event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthEventKind {
    /// Signup was requested.
    SignupRequested,
    /// Email was verified.
    EmailVerified,
    /// Signin succeeded.
    SignInSucceeded,
    /// Signin failed.
    SignInFailed,
    /// Password reset was requested.
    PasswordResetRequested,
    /// Password was reset.
    PasswordResetCompleted,
    /// Session was revoked.
    SessionRevoked,
}

/// Persisted auth event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEventRecord {
    /// Event id.
    pub id: AuthEventId,
    /// Optional linked user.
    pub user_id: Option<UserId>,
    /// Optional linked canonical email.
    pub email_canonical: Option<CanonicalEmail>,
    /// Event kind.
    pub kind: AuthEventKind,
    /// Event timestamp.
    pub occurred_at: UnixTimestampMicros,
    /// Hashed IP metadata.
    pub ip_hash: Option<TokenHash>,
    /// Hashed user-agent metadata.
    pub user_agent_hash: Option<TokenHash>,
    /// Stable non-secret detail code.
    pub detail_code: Option<String>,
}

/// Input for creating a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserInput {
    /// User id to persist.
    pub id: UserId,
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

/// Input for fetching a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetUserInput {
    /// User id to fetch.
    pub user_id: UserId,
}

/// Input for creating a user email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserEmailInput {
    /// Email row id.
    pub id: UserEmailId,
    /// Owning user id.
    pub user_id: UserId,
    /// Original email spelling.
    pub email_original: String,
    /// Canonical email lookup key.
    pub email_canonical: CanonicalEmail,
    /// Whether this is the primary email.
    pub is_primary: bool,
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

/// Input for canonical email lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindEmailByCanonicalInput {
    /// Canonical email lookup key.
    pub email_canonical: CanonicalEmail,
}

/// Input for marking an email verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkEmailVerifiedInput {
    /// Canonical email lookup key.
    pub email_canonical: CanonicalEmail,
    /// Verification timestamp.
    pub verified_at: UnixTimestampMicros,
}

/// Input for inserting or updating a password credential.
#[derive(Clone, PartialEq, Eq)]
pub struct InsertPasswordInput {
    /// Owning user id.
    pub user_id: UserId,
    /// PHC password hash.
    pub password_hash: PasswordHashString,
    /// Timestamp when the password was set.
    pub password_set_at: UnixTimestampMicros,
    /// Application credential version.
    pub password_version: i64,
}

/// Input for atomically creating a password-backed user.
#[derive(Clone, PartialEq, Eq)]
pub struct CreatePasswordUserInput {
    /// User id to persist.
    pub user_id: UserId,
    /// Email row id to persist.
    pub email_id: UserEmailId,
    /// Original email spelling.
    pub email_original: String,
    /// Canonical email lookup key.
    pub email_canonical: CanonicalEmail,
    /// PHC password hash.
    pub password_hash: PasswordHashString,
    /// Timestamp when the password was set.
    pub password_set_at: UnixTimestampMicros,
    /// Application credential version.
    pub password_version: i64,
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

impl core::fmt::Debug for CreatePasswordUserInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CreatePasswordUserInput")
            .field("user_id", &self.user_id)
            .field("email_id", &self.email_id)
            .field("email_original", &self.email_original)
            .field("email_canonical", &self.email_canonical)
            .field("password_hash", &"[REDACTED]")
            .field("password_set_at", &self.password_set_at)
            .field("password_version", &self.password_version)
            .field("now", &self.now)
            .finish()
    }
}

/// Output from atomically creating a password-backed user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePasswordUserOutput {
    /// Created user.
    pub user: UserRecord,
    /// Created primary email.
    pub email: UserEmailRecord,
    /// Created password credential.
    pub credential: PasswordCredentialRecord,
}

/// Input for atomically creating a verified passwordless email account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVerifiedEmailUserInput {
    /// User id to persist.
    pub user_id: UserId,
    /// Email row id to persist.
    pub email_id: UserEmailId,
    /// Original email spelling.
    pub email_original: String,
    /// Canonical email lookup key.
    pub email_canonical: CanonicalEmail,
    /// Verification timestamp.
    pub verified_at: UnixTimestampMicros,
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

/// Output from atomically creating a verified passwordless email account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVerifiedEmailUserOutput {
    /// Created user.
    pub user: UserRecord,
    /// Created verified primary email.
    pub email: UserEmailRecord,
}

impl core::fmt::Debug for InsertPasswordInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InsertPasswordInput")
            .field("user_id", &self.user_id)
            .field("password_hash", &"[REDACTED]")
            .field("password_set_at", &self.password_set_at)
            .field("password_version", &self.password_version)
            .finish()
    }
}

/// Input for fetching a password credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPasswordCredentialInput {
    /// Owning user id.
    pub user_id: UserId,
}

/// Input for creating a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateChallengeInput {
    /// Challenge id.
    pub id: ChallengeId,
    /// Challenge purpose.
    pub purpose: ChallengePurpose,
    /// Optional linked user.
    pub user_id: Option<UserId>,
    /// Canonical target email.
    pub email_canonical: CanonicalEmail,
    /// Hash of the challenge secret.
    pub secret_hash: TokenHash,
    /// Delivery style.
    pub delivery: ChallengeDelivery,
    /// Optional validated redirect path.
    pub redirect_path: Option<RedirectPath>,
    /// Expiry timestamp.
    pub expires_at: UnixTimestampMicros,
    /// Maximum failed attempts.
    pub max_attempts: RetryBudget,
    /// Earliest resend timestamp.
    pub resend_after: UnixTimestampMicros,
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

/// Input for fetching a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetChallengeInput {
    /// Challenge id.
    pub challenge_id: ChallengeId,
}

/// Input for incrementing challenge attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementChallengeAttemptsInput {
    /// Challenge id.
    pub challenge_id: ChallengeId,
}

/// Input for consuming a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionInput {
    /// Session row id.
    pub id: SessionId,
    /// Owning user id.
    pub user_id: UserId,
    /// Hash of the browser token.
    pub token_hash: TokenHash,
    /// Creation timestamp.
    pub created_at: UnixTimestampMicros,
    /// Idle expiry timestamp.
    pub idle_expires_at: UnixTimestampMicros,
    /// Absolute expiry timestamp.
    pub absolute_expires_at: UnixTimestampMicros,
    /// Hashed IP metadata.
    pub ip_hash: Option<TokenHash>,
    /// Hashed user-agent metadata.
    pub user_agent_hash: Option<TokenHash>,
}

/// Input for fetching a session by token hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSessionInput {
    /// Hash of the browser token.
    pub token_hash: TokenHash,
}

/// Input for updating session last-seen timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSessionLastSeenInput {
    /// Session row id.
    pub session_id: SessionId,
    /// New last-seen timestamp.
    pub last_seen_at: UnixTimestampMicros,
}

/// Input for revoking one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeSessionInput {
    /// Session row id.
    pub session_id: SessionId,
    /// Revocation timestamp.
    pub revoked_at: UnixTimestampMicros,
}

/// Input for revoking all sessions for a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeUserSessionsInput {
    /// User whose sessions should be revoked.
    pub user_id: UserId,
    /// Revocation timestamp.
    pub revoked_at: UnixTimestampMicros,
}

/// Input for deleting expired sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteExpiredSessionsInput {
    /// Current timestamp.
    pub now: UnixTimestampMicros,
}

/// Input for incrementing a rate-limit counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementRateLimitInput {
    /// Rate limit scope.
    pub scope: String,
    /// Hashed rate-limit key.
    pub key_hash: TokenHash,
    /// Current window start timestamp.
    pub window_start: UnixTimestampMicros,
    /// Maximum count allowed in the window.
    pub max_count: RetryBudget,
}

/// Rate-limit decision after incrementing a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Count after this increment.
    pub count: usize,
    /// Whether the request is allowed.
    pub allowed: bool,
}

/// Input for appending an auth event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendAuthEventInput {
    /// Event id.
    pub id: AuthEventId,
    /// Optional linked user.
    pub user_id: Option<UserId>,
    /// Optional linked canonical email.
    pub email_canonical: Option<CanonicalEmail>,
    /// Event kind.
    pub kind: AuthEventKind,
    /// Event timestamp.
    pub occurred_at: UnixTimestampMicros,
    /// Hashed IP metadata.
    pub ip_hash: Option<TokenHash>,
    /// Hashed user-agent metadata.
    pub user_agent_hash: Option<TokenHash>,
    /// Stable non-secret detail code.
    pub detail_code: Option<String>,
}

/// User storage operations.
pub trait UserStore: Clone + Send + Sync + 'static {
    /// Creates a user row.
    ///
    /// Implementations must fail with [`crate::StoreErrorCode::Conflict`] if
    /// the id already exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or the user id conflicts.
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> impl Future<Output = Result<UserRecord, StoreError>> + Send;

    /// Fetches a user by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn get_user(
        &self,
        input: GetUserInput,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;
}

/// User email storage operations.
pub trait UserEmailStore: Clone + Send + Sync + 'static {
    /// Inserts a user email.
    ///
    /// Implementations must enforce uniqueness for canonical email addresses.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or the canonical email
    /// already exists.
    fn create_user_email(
        &self,
        input: CreateUserEmailInput,
    ) -> impl Future<Output = Result<UserEmailRecord, StoreError>> + Send;

    /// Finds a user email by canonical address.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn find_email_by_canonical(
        &self,
        input: FindEmailByCanonicalInput,
    ) -> impl Future<Output = Result<Option<UserEmailRecord>, StoreError>> + Send;

    /// Marks an email address verified.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn mark_email_verified(
        &self,
        input: MarkEmailVerifiedInput,
    ) -> impl Future<Output = Result<Option<UserEmailRecord>, StoreError>> + Send;
}

/// Password credential storage operations.
pub trait PasswordCredentialStore: Clone + Send + Sync + 'static {
    /// Inserts or updates a password credential.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn upsert_password_credential(
        &self,
        input: InsertPasswordInput,
    ) -> impl Future<Output = Result<PasswordCredentialRecord, StoreError>> + Send;

    /// Fetches a password credential by user id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn get_password_credential(
        &self,
        input: GetPasswordCredentialInput,
    ) -> impl Future<Output = Result<Option<PasswordCredentialRecord>, StoreError>> + Send;
}

/// Challenge storage operations.
pub trait ChallengeStore: Clone + Send + Sync + 'static {
    /// Creates a challenge.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or the challenge id
    /// conflicts.
    fn create_challenge(
        &self,
        input: CreateChallengeInput,
    ) -> impl Future<Output = Result<ChallengeRecord, StoreError>> + Send;

    /// Fetches a challenge by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn get_challenge(
        &self,
        input: GetChallengeInput,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send;

    /// Increments challenge attempts and returns the updated challenge.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn increment_challenge_attempts(
        &self,
        input: IncrementChallengeAttemptsInput,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send;

    /// Consumes a challenge atomically if it has not already been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn consume_challenge(
        &self,
        input: GetChallengeInput,
        consumed_at: UnixTimestampMicros,
    ) -> impl Future<Output = Result<Option<ChallengeRecord>, StoreError>> + Send;
}

/// Session storage operations.
pub trait SessionStore: Clone + Send + Sync + 'static {
    /// Creates a session row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or the session/token hash
    /// conflicts.
    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> impl Future<Output = Result<SessionRecord, StoreError>> + Send;

    /// Fetches a session by token hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn get_session_by_token_hash(
        &self,
        input: GetSessionInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send;

    /// Updates a session's last-seen timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn update_session_last_seen(
        &self,
        input: UpdateSessionLastSeenInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send;

    /// Revokes one session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn revoke_session(
        &self,
        input: RevokeSessionInput,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send;

    /// Revokes all active sessions for a user.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn revoke_user_sessions(
        &self,
        input: RevokeUserSessionsInput,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Deletes expired session rows and returns the number removed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn delete_expired_sessions(
        &self,
        input: DeleteExpiredSessionsInput,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// Rate-limit storage operations.
pub trait RateLimitStore: Clone + Send + Sync + 'static {
    /// Increments a rate-limit window counter atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn increment_rate_limit(
        &self,
        input: IncrementRateLimitInput,
    ) -> impl Future<Output = Result<RateLimitDecision, StoreError>> + Send;
}

/// Auth event storage operations.
pub trait AuthEventStore: Clone + Send + Sync + 'static {
    /// Appends an auth event.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails.
    fn append_auth_event(
        &self,
        input: AppendAuthEventInput,
    ) -> impl Future<Output = Result<AuthEventRecord, StoreError>> + Send;
}

/// Cross-table account creation operations.
pub trait AccountStore: Clone + Send + Sync + 'static {
    /// Creates a user, primary email, and password credential atomically.
    ///
    /// Implementations must fail without committing partial rows if any user
    /// id, email id, or canonical email uniqueness constraint rejects the
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or a unique constraint
    /// conflicts.
    fn create_password_user(
        &self,
        input: CreatePasswordUserInput,
    ) -> impl Future<Output = Result<CreatePasswordUserOutput, StoreError>> + Send;

    /// Creates a user and verified primary email atomically.
    ///
    /// Implementations must fail without committing partial rows if any user
    /// id, email id, or canonical email uniqueness constraint rejects the
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when persistence fails or a unique constraint
    /// conflicts.
    fn create_verified_email_user(
        &self,
        input: CreateVerifiedEmailUserInput,
    ) -> impl Future<Output = Result<CreateVerifiedEmailUserOutput, StoreError>> + Send;
}

/// Composite Harbor auth store.
pub trait AuthStore:
    UserStore
    + UserEmailStore
    + PasswordCredentialStore
    + ChallengeStore
    + SessionStore
    + RateLimitStore
    + AuthEventStore
    + AccountStore
{
}

impl<T> AuthStore for T where
    T: UserStore
        + UserEmailStore
        + PasswordCredentialStore
        + ChallengeStore
        + SessionStore
        + RateLimitStore
        + AuthEventStore
        + AccountStore
{
}
