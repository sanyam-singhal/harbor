//! Core domain types and service contracts for Harbor.
//!
//! This crate intentionally has no web framework, database, or email provider
//! dependency. It owns the invariants that all Harbor integrations must obey.

pub mod domain;

/// Version of the `harbor-core` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use domain::{
    CanonicalEmail, ChallengeId, EmailAddress, RedirectPath, RetryBudget, SecretToken, SessionId,
    TokenHash, UnixTimestampMicros, UserId,
};
