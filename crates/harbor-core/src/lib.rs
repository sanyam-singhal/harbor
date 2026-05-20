//! Core domain types and service contracts for Harbor.
//!
//! This crate intentionally has no web framework, database, or email provider
//! dependency. It owns the invariants that all Harbor integrations must obey.

pub mod domain;
pub mod error;
pub mod password;
pub mod ports;
pub mod secret;
pub mod service;
pub mod store;

/// Version of the `harbor-core` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use domain::{
    AuthEventId, CanonicalEmail, ChallengeId, DomainError, EmailAddress, RedirectPath, RetryBudget,
    SecretToken, SessionId, TokenHash, UnixTimestampMicros, UserEmailId, UserId,
};
pub use error::{
    AuthError, AuthErrorCode, ConfigError, ConfigErrorCode, MailError, MailErrorCode, StoreError,
    StoreErrorCode,
};
pub use password::{
    Argon2Params, Argon2PasswordHasher, CommonPasswordBlocklist, PasswordBlocklist, PasswordError,
    PasswordHashError, PasswordHashString, PasswordPolicy, PasswordVerification,
};
pub use ports::{
    Clock, RandomError, SecretGenerator, SystemClock, SystemSecretGenerator, new_auth_event_id,
    new_challenge_id, new_session_id, new_user_email_id, new_user_id, random_otp_code,
    random_session_token, random_url_token,
};
pub use secret::{
    HmacSecretKey, SecretHashPurpose, constant_time_token_hash_eq, hash_secret, hash_secret_token,
};
pub use service::{
    AuthRateLimitScope, AuthService, ChallengePolicy, CurrentSession, EmailChallengeInput,
    EmailChallengeOutput, EmailChallengeSignInInput, EmailChallengeSignInOutput,
    EmailChallengeSignInPolicy, PasswordSignInInput, PasswordSignInOutput, PasswordSignUpInput,
    PasswordSignUpOutput, PasswordlessSignup, RateLimitInput, RequestPasswordResetInput,
    RequestPasswordResetOutput, ResetPasswordInput, ResetPasswordOutput, VerifiedChallenge,
    VerifyChallengeInput,
};
pub use store::{
    AccountStore, AppendAuthEventInput, AuthEventKind, AuthEventRecord, AuthEventStore, AuthStore,
    ChallengeDelivery, ChallengePurpose, ChallengeRecord, ChallengeStore, CreateChallengeInput,
    CreatePasswordUserInput, CreatePasswordUserOutput, CreateSessionInput, CreateUserEmailInput,
    CreateUserInput, CreateVerifiedEmailUserInput, CreateVerifiedEmailUserOutput,
    DeleteExpiredSessionsInput, FindEmailByCanonicalInput, GetChallengeInput,
    GetPasswordCredentialInput, GetSessionInput, GetUserInput, IncrementChallengeAttemptsInput,
    IncrementRateLimitInput, InsertPasswordInput, MarkEmailVerifiedInput, PasswordCredentialRecord,
    PasswordCredentialStore, RateLimitDecision, RateLimitStore, RevokeSessionInput,
    RevokeUserSessionsInput, SessionRecord, SessionStore, UpdateSessionLastSeenInput,
    UserEmailRecord, UserEmailStore, UserRecord, UserStore,
};
