//! Core domain types and service contracts for Harbor.
//!
//! This crate intentionally has no web framework, database, or email provider
//! dependency. It owns the invariants that all Harbor integrations must obey.

pub mod domain;
pub mod error;
pub mod password;
pub mod ports;
pub mod secret;

/// Version of the `harbor-core` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use domain::{
    CanonicalEmail, ChallengeId, DomainError, EmailAddress, RedirectPath, RetryBudget, SecretToken,
    SessionId, TokenHash, UnixTimestampMicros, UserId,
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
    Clock, RandomError, SecretGenerator, SystemClock, SystemSecretGenerator, new_challenge_id,
    new_session_id, new_user_id, random_otp_code, random_session_token, random_url_token,
};
pub use secret::{
    HmacSecretKey, SecretHashPurpose, constant_time_token_hash_eq, hash_secret, hash_secret_token,
};
