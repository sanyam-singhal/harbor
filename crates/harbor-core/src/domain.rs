//! Validated domain newtypes shared by Harbor services and integrations.

use core::fmt;
use core::num::NonZeroUsize;
use std::borrow::Cow;

const MAX_EMAIL_BYTES: usize = 254;
const MAX_LOCAL_PART_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_REDIRECT_PATH_BYTES: usize = 2048;
const MAX_SECRET_TOKEN_BYTES: usize = 4096;
const MIN_OPAQUE_ID_BYTES: usize = 16;
const MAX_OPAQUE_ID_BYTES: usize = 128;

/// Error returned when a domain newtype rejects an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    /// The value is empty.
    Empty,
    /// The value is longer than Harbor accepts.
    TooLong,
    /// The value contains a character or byte pattern that is not permitted.
    InvalidCharacters,
    /// The value does not have the required shape for the target type.
    InvalidFormat,
    /// The numeric value is outside the permitted bounds.
    OutOfRange,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "value is empty",
            Self::TooLong => "value is too long",
            Self::InvalidCharacters => "value contains invalid characters",
            Self::InvalidFormat => "value has an invalid format",
            Self::OutOfRange => "value is outside the permitted range",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DomainError {}

/// Stable user identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(String);

/// Stable browser session row identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

/// Stable email challenge row identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChallengeId(String);

/// Stable user email row identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserEmailId(String);

/// Stable auth event row identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthEventId(String);

macro_rules! opaque_id_type {
    ($type_name:ident) => {
        impl $type_name {
            /// Creates a validated opaque identifier.
            ///
            /// # Errors
            ///
            /// Returns [`DomainError`] when the identifier is empty, too short,
            /// too long, or contains characters outside Harbor's opaque ID
            /// alphabet.
            pub fn try_new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                validate_opaque_id(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($type_name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $type_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

opaque_id_type!(UserId);
opaque_id_type!(SessionId);
opaque_id_type!(ChallengeId);
opaque_id_type!(UserEmailId);
opaque_id_type!(AuthEventId);

/// User-supplied email address plus Harbor's canonical lookup form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    original: String,
    canonical: CanonicalEmail,
}

impl EmailAddress {
    /// Parses and canonicalizes an email address.
    ///
    /// Harbor v0.1 intentionally uses a conservative email shape for account
    /// identifiers. It rejects whitespace, control characters, quoted local
    /// parts, IP-literal domains, and domains without a dot. The canonical form
    /// lowercases the full address for stable login lookup.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the email address is empty, too long, or
    /// does not match Harbor's accepted email shape.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let original = value.into();
        let canonical = canonicalize_email(&original)?;
        Ok(Self {
            original,
            canonical: CanonicalEmail(canonical),
        })
    }

    /// Returns the original email spelling accepted from the user.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Returns Harbor's canonical email lookup value.
    #[must_use]
    pub fn canonical(&self) -> &CanonicalEmail {
        &self.canonical
    }
}

/// Canonical email lookup key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalEmail(String);

impl CanonicalEmail {
    /// Creates a canonical email after validating that it is already canonical.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the value is not a valid Harbor email
    /// address or differs from its canonical lowercase form.
    pub fn try_new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let canonical = canonicalize_email(&value)?;
        if value != canonical {
            return Err(DomainError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Returns the canonical email as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalEmail")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// UTC timestamp represented as Unix microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnixTimestampMicros(i64);

impl UnixTimestampMicros {
    /// Unix epoch.
    pub const EPOCH: Self = Self(0);

    /// Creates a non-negative Unix timestamp in microseconds.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::OutOfRange`] when the timestamp is negative.
    pub const fn try_new(value: i64) -> Result<Self, DomainError> {
        if value < 0 {
            return Err(DomainError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Returns the timestamp as raw Unix microseconds.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }

    /// Adds microseconds, returning `None` on overflow.
    #[must_use]
    pub fn checked_add_micros(self, micros: i64) -> Option<Self> {
        self.0.checked_add(micros).and_then(
            |value| {
                if value < 0 { None } else { Some(Self(value)) }
            },
        )
    }
}

/// Positive retry or attempt budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RetryBudget(NonZeroUsize);

impl RetryBudget {
    /// Maximum retry budget accepted by default constructors.
    pub const MAX: usize = 10_000;

    /// Creates a retry budget.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::OutOfRange`] for zero or excessively large
    /// budgets.
    pub const fn try_new(value: usize) -> Result<Self, DomainError> {
        if value == 0 || value > Self::MAX {
            return Err(DomainError::OutOfRange);
        }
        match NonZeroUsize::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(DomainError::OutOfRange),
        }
    }

    /// Returns the retry budget as a `usize`.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// Same-origin relative redirect path.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RedirectPath(String);

impl RedirectPath {
    /// Creates a relative redirect path.
    ///
    /// Accepted values must start with `/`, must not start with `//`, must not
    /// contain backslashes or control characters, and must fit within Harbor's
    /// redirect path length limit.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the path could escape the current origin or
    /// has invalid characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_redirect_path(&value)?;
        Ok(Self(value))
    }

    /// Returns the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedirectPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RedirectPath")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for RedirectPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Secret token value that must not be logged.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretToken(String);

impl SecretToken {
    /// Creates a secret token wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the token is empty, too long, or contains
    /// control characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::Empty);
        }
        if value.len() > MAX_SECRET_TOKEN_BYTES {
            return Err(DomainError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    /// Exposes the secret value to code that needs to hash or transmit it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// Hash of a secret token or OTP code.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenHash(Vec<u8>);

impl TokenHash {
    /// Creates a token hash from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the hash is empty.
    pub fn try_new(value: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the hash bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenHash([REDACTED])")
    }
}

fn validate_opaque_id(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() < MIN_OPAQUE_ID_BYTES || value.len() > MAX_OPAQUE_ID_BYTES {
        return Err(DomainError::OutOfRange);
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        Err(DomainError::InvalidCharacters)
    }
}

fn canonicalize_email(value: &str) -> Result<String, DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() > MAX_EMAIL_BYTES {
        return Err(DomainError::TooLong);
    }
    if value.trim() != value || value.chars().any(|character| character.is_control()) {
        return Err(DomainError::InvalidCharacters);
    }

    let (local, domain) = value.split_once('@').ok_or(DomainError::InvalidFormat)?;
    if value.matches('@').count() != 1 {
        return Err(DomainError::InvalidFormat);
    }
    validate_local_part(local)?;
    validate_domain(domain)?;

    Ok(format!(
        "{}@{}",
        local.to_ascii_lowercase(),
        domain.to_ascii_lowercase()
    ))
}

fn validate_local_part(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() > MAX_LOCAL_PART_BYTES {
        return Err(DomainError::TooLong);
    }
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(DomainError::InvalidFormat);
    }
    if value.bytes().all(is_accepted_local_part_byte) {
        Ok(())
    } else {
        Err(DomainError::InvalidCharacters)
    }
}

fn validate_domain(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() > MAX_DOMAIN_BYTES {
        return Err(DomainError::TooLong);
    }
    if !value.contains('.') {
        return Err(DomainError::InvalidFormat);
    }
    for label in value.split('.') {
        validate_domain_label(label)?;
    }
    Ok(())
}

fn validate_domain_label(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::InvalidFormat);
    }
    if value.starts_with('-') || value.ends_with('-') {
        return Err(DomainError::InvalidFormat);
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(DomainError::InvalidCharacters)
    }
}

fn validate_redirect_path(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() > MAX_REDIRECT_PATH_BYTES {
        return Err(DomainError::TooLong);
    }
    if !value.starts_with('/') || value.starts_with("//") {
        return Err(DomainError::InvalidFormat);
    }
    if value.contains('\\') || value.chars().any(char::is_control) {
        return Err(DomainError::InvalidCharacters);
    }
    Ok(())
}

fn is_accepted_local_part_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'.'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'/'
            | b'='
            | b'?'
            | b'^'
            | b'_'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
            | b'~'
    )
}

impl From<UserId> for String {
    fn from(value: UserId) -> Self {
        value.0
    }
}

impl From<SessionId> for String {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

impl From<ChallengeId> for String {
    fn from(value: ChallengeId) -> Self {
        value.0
    }
}

impl From<UserEmailId> for String {
    fn from(value: UserEmailId) -> Self {
        value.0
    }
}

impl From<AuthEventId> for String {
    fn from(value: AuthEventId) -> Self {
        value.0
    }
}

impl<'a> From<&'a EmailAddress> for Cow<'a, str> {
    fn from(value: &'a EmailAddress) -> Self {
        Cow::Borrowed(value.original())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalEmail, ChallengeId, DomainError, EmailAddress, RedirectPath, RetryBudget,
        SecretToken, SessionId, TokenHash, UnixTimestampMicros, UserId,
    };

    #[test]
    fn opaque_ids_accept_expected_alphabet() {
        let id = "abcDEF0123456789_-";

        assert!(UserId::try_new(id).is_ok());
        assert!(SessionId::try_new(id).is_ok());
        assert!(ChallengeId::try_new(id).is_ok());
        assert!(super::UserEmailId::try_new(id).is_ok());
        assert!(super::AuthEventId::try_new(id).is_ok());
    }

    #[test]
    fn opaque_ids_reject_invalid_space() {
        assert_eq!(UserId::try_new("").err(), Some(DomainError::Empty));
        assert_eq!(
            UserId::try_new("short").err(),
            Some(DomainError::OutOfRange)
        );
        assert_eq!(
            UserId::try_new("abcDEF0123456789!").err(),
            Some(DomainError::InvalidCharacters)
        );
    }

    #[test]
    fn email_parse_preserves_original_and_builds_canonical_lookup() -> Result<(), DomainError> {
        let email = EmailAddress::parse("User.Name+Tag@Example.COM")?;

        assert_eq!(email.original(), "User.Name+Tag@Example.COM");
        assert_eq!(email.canonical().as_str(), "user.name+tag@example.com");
        Ok(())
    }

    #[test]
    fn email_parse_rejects_ambiguous_or_unbounded_values() {
        assert!(EmailAddress::parse("").is_err());
        assert!(EmailAddress::parse(" user@example.com").is_err());
        assert!(EmailAddress::parse("user@@example.com").is_err());
        assert!(EmailAddress::parse("user@example").is_err());
        assert!(EmailAddress::parse(".user@example.com").is_err());
        assert!(EmailAddress::parse("user@example..com").is_err());
    }

    #[test]
    fn canonical_email_must_already_be_canonical() {
        assert!(CanonicalEmail::try_new("user@example.com").is_ok());
        assert_eq!(
            CanonicalEmail::try_new("User@example.com").err(),
            Some(DomainError::InvalidFormat)
        );
    }

    #[test]
    fn redirect_path_allows_only_same_origin_paths() {
        assert!(RedirectPath::try_new("/account?tab=sessions").is_ok());
        assert!(RedirectPath::try_new("https://example.com").is_err());
        assert!(RedirectPath::try_new("//example.com").is_err());
        assert!(RedirectPath::try_new("/account\\evil").is_err());
    }

    #[test]
    fn timestamps_and_retry_budgets_enforce_bounds() {
        assert_eq!(
            UnixTimestampMicros::try_new(42).map(UnixTimestampMicros::as_i64),
            Ok(42)
        );
        assert!(UnixTimestampMicros::try_new(-1).is_err());
        assert_eq!(
            UnixTimestampMicros::EPOCH
                .checked_add_micros(5)
                .map(UnixTimestampMicros::as_i64),
            Some(5)
        );
        assert!(RetryBudget::try_new(1).is_ok());
        assert!(RetryBudget::try_new(0).is_err());
        assert!(RetryBudget::try_new(RetryBudget::MAX + 1).is_err());
    }

    #[test]
    fn secret_debug_output_is_redacted() -> Result<(), DomainError> {
        let token = SecretToken::try_new("secret-token")?;
        let hash = TokenHash::try_new(vec![1, 2, 3])?;

        assert_eq!(format!("{token:?}"), "SecretToken([REDACTED])");
        assert_eq!(format!("{hash:?}"), "TokenHash([REDACTED])");
        assert_eq!(token.expose_secret(), "secret-token");
        assert_eq!(hash.as_bytes(), &[1, 2, 3]);
        Ok(())
    }
}
