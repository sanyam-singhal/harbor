//! Shared typed errors for Harbor.

use core::fmt;

/// Stable authentication error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthErrorCode {
    /// Submitted credentials did not authenticate a user.
    InvalidCredentials,
    /// Email verification is required before this operation can continue.
    EmailNotVerified,
    /// The request exceeded a configured rate limit.
    RateLimited,
    /// CSRF validation failed.
    Csrf,
    /// The session is missing, expired, or revoked.
    SessionExpired,
    /// The authenticated principal cannot perform this action.
    Forbidden,
    /// Storage failed.
    Store,
    /// Email delivery failed.
    Mail,
    /// Configuration is invalid.
    Config,
    /// An internal invariant failed.
    Internal,
}

impl AuthErrorCode {
    /// Returns the stable machine-readable code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::EmailNotVerified => "email_not_verified",
            Self::RateLimited => "rate_limited",
            Self::Csrf => "csrf_failed",
            Self::SessionExpired => "session_expired",
            Self::Forbidden => "forbidden",
            Self::Store => "store_error",
            Self::Mail => "mail_error",
            Self::Config => "config_error",
            Self::Internal => "internal_error",
        }
    }
}

/// Error returned by Harbor authentication services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    code: AuthErrorCode,
    detail: Option<&'static str>,
}

impl AuthError {
    /// Creates an auth error with no internal detail.
    #[must_use]
    pub const fn new(code: AuthErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// Creates an auth error with a stable internal detail code.
    #[must_use]
    pub const fn with_detail(code: AuthErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> AuthErrorCode {
        self.code
    }

    /// Returns an optional stable internal detail code.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        self.detail
    }

    /// Returns the user-facing message. It intentionally avoids revealing
    /// whether accounts, emails, tokens, or sessions exist.
    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        match self.code {
            AuthErrorCode::InvalidCredentials => "The submitted credentials are invalid.",
            AuthErrorCode::EmailNotVerified => "Please verify your email address to continue.",
            AuthErrorCode::RateLimited => "Too many attempts. Please try again later.",
            AuthErrorCode::Csrf => "The form expired. Please try again.",
            AuthErrorCode::SessionExpired => "Please sign in again.",
            AuthErrorCode::Forbidden => "You cannot perform this action.",
            AuthErrorCode::Store
            | AuthErrorCode::Mail
            | AuthErrorCode::Config
            | AuthErrorCode::Internal => "Authentication is temporarily unavailable.",
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.user_message())
    }
}

impl std::error::Error for AuthError {}

/// Stable storage error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreErrorCode {
    /// A record was not found.
    NotFound,
    /// A uniqueness or state conflict occurred.
    Conflict,
    /// Stored data violated Harbor's expected format.
    CorruptData,
    /// A transaction failed or rolled back.
    Transaction,
    /// The store is unavailable.
    Unavailable,
    /// An internal storage invariant failed.
    Internal,
}

impl StoreErrorCode {
    /// Returns the stable machine-readable code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::CorruptData => "corrupt_data",
            Self::Transaction => "transaction",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

/// Error returned by Harbor stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    code: StoreErrorCode,
    detail: Option<&'static str>,
}

impl StoreError {
    /// Creates a store error.
    #[must_use]
    pub const fn new(code: StoreErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// Creates a store error with a stable internal detail code.
    #[must_use]
    pub const fn with_detail(code: StoreErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> StoreErrorCode {
        self.code
    }

    /// Returns an optional stable internal detail code.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        self.detail
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("storage operation failed")
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for AuthError {
    fn from(value: StoreError) -> Self {
        Self::with_detail(AuthErrorCode::Store, value.code.as_str())
    }
}

/// Stable email delivery error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MailErrorCode {
    /// Email provider configuration is invalid.
    InvalidConfig,
    /// Provider rejected the message.
    Rejected,
    /// Provider rate limit was exceeded.
    RateLimited,
    /// Provider is unavailable.
    Unavailable,
    /// An internal email invariant failed.
    Internal,
}

impl MailErrorCode {
    /// Returns the stable machine-readable code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

/// Error returned by Harbor email integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailError {
    code: MailErrorCode,
    detail: Option<&'static str>,
}

impl MailError {
    /// Creates a mail error.
    #[must_use]
    pub const fn new(code: MailErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// Creates a mail error with a stable internal detail code.
    #[must_use]
    pub const fn with_detail(code: MailErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> MailErrorCode {
        self.code
    }

    /// Returns an optional stable internal detail code.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        self.detail
    }
}

impl fmt::Display for MailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("email delivery failed")
    }
}

impl std::error::Error for MailError {}

impl From<MailError> for AuthError {
    fn from(value: MailError) -> Self {
        Self::with_detail(AuthErrorCode::Mail, value.code.as_str())
    }
}

/// Stable configuration error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigErrorCode {
    /// Required configuration is missing.
    Missing,
    /// Configuration is malformed.
    Invalid,
    /// A secret is too short for Harbor's security requirements.
    WeakSecret,
    /// A configured URL is not accepted.
    InvalidUrl,
    /// An internal config invariant failed.
    Internal,
}

impl ConfigErrorCode {
    /// Returns the stable machine-readable code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::WeakSecret => "weak_secret",
            Self::InvalidUrl => "invalid_url",
            Self::Internal => "internal",
        }
    }
}

/// Error returned by Harbor configuration builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    code: ConfigErrorCode,
    detail: Option<&'static str>,
}

impl ConfigError {
    /// Creates a configuration error.
    #[must_use]
    pub const fn new(code: ConfigErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// Creates a configuration error with a stable internal detail code.
    #[must_use]
    pub const fn with_detail(code: ConfigErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ConfigErrorCode {
        self.code
    }

    /// Returns an optional stable internal detail code.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        self.detail
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("configuration is invalid")
    }
}

impl std::error::Error for ConfigError {}

impl From<ConfigError> for AuthError {
    fn from(value: ConfigError) -> Self {
        Self::with_detail(AuthErrorCode::Config, value.code.as_str())
    }
}

#[cfg(test)]
mod tests;
