//! Errors returned by Harbor test-support helpers.

use std::fmt;

use harbor_core::{DomainError, PasswordError, PasswordHashError};

/// Error returned by fallible test-support helpers.
#[derive(Debug)]
#[non_exhaustive]
pub enum TestSupportError {
    /// A Harbor domain value rejected a test fixture value.
    Domain(DomainError),
    /// Password policy or Argon2 test parameters were invalid.
    PasswordHash(PasswordHashError),
    /// A password policy fixture was invalid.
    Password(PasswordError),
    /// A filesystem fixture could not be created or prepared.
    Io(std::io::Error),
}

impl fmt::Display for TestSupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => write!(formatter, "domain fixture failed: {error}"),
            Self::PasswordHash(error) => write!(formatter, "password fixture failed: {error}"),
            Self::Password(error) => write!(formatter, "password policy fixture failed: {error}"),
            Self::Io(error) => write!(formatter, "filesystem fixture failed: {error}"),
        }
    }
}

impl std::error::Error for TestSupportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            Self::PasswordHash(error) => Some(error),
            Self::Password(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<DomainError> for TestSupportError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}

impl From<PasswordHashError> for TestSupportError {
    fn from(value: PasswordHashError) -> Self {
        Self::PasswordHash(value)
    }
}

impl From<PasswordError> for TestSupportError {
    fn from(value: PasswordError) -> Self {
        Self::Password(value)
    }
}

impl From<std::io::Error> for TestSupportError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
