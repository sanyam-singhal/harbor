//! Core domain types and service contracts for Harbor.
//!
//! This crate intentionally has no web framework, database, or email provider
//! dependency. It owns the invariants that all Harbor integrations must obey.

pub mod domain;
pub mod ports;

/// Version of the `harbor-core` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use domain::{
    CanonicalEmail, ChallengeId, EmailAddress, RedirectPath, RetryBudget, SecretToken, SessionId,
    TokenHash, UnixTimestampMicros, UserId,
};
pub use ports::{
    Clock, RandomError, SecretGenerator, SystemClock, SystemSecretGenerator, new_challenge_id,
    new_session_id, new_user_id, random_otp_code, random_session_token, random_url_token,
};
