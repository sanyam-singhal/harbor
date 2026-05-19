//! Validated Harbor configuration for Leptos applications.

use core::fmt;
use std::sync::Arc;

use harbor_core::{
    ConfigError, ConfigErrorCode, HmacSecretKey, PasswordPolicy, RetryBudget, UnixTimestampMicros,
};
use harbor_email::AuthEmailRenderer;

use crate::{CookieDefaults, HeaderName};

const MAX_BASE_URL_BYTES: usize = 2048;
const DEFAULT_RATE_LIMIT_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;
const DEFAULT_SIGNUP_CHALLENGE_MICROS: i64 = 30 * 60 * 1_000_000;
const DEFAULT_EMAIL_SIGNIN_CHALLENGE_MICROS: i64 = 10 * 60 * 1_000_000;
const DEFAULT_PASSWORD_RESET_CHALLENGE_MICROS: i64 = 15 * 60 * 1_000_000;

/// Validated Harbor configuration.
#[derive(Clone)]
pub struct HarborConfig {
    public_base_url: PublicBaseUrl,
    cookie_defaults: CookieDefaults,
    csrf_header_name: HeaderName,
    hmac_secret_key: HmacSecretKey,
    password_policy: PasswordPolicy,
    challenge_lifetimes: ChallengeLifetimes,
    rate_limits: AuthRateLimits,
    email_renderer: Arc<dyn AuthEmailRenderer>,
}

impl HarborConfig {
    /// Returns the public base URL.
    #[must_use]
    pub const fn public_base_url(&self) -> &PublicBaseUrl {
        &self.public_base_url
    }

    /// Returns cookie defaults.
    #[must_use]
    pub const fn cookie_defaults(&self) -> &CookieDefaults {
        &self.cookie_defaults
    }

    /// Returns the CSRF header name.
    #[must_use]
    pub const fn csrf_header_name(&self) -> &HeaderName {
        &self.csrf_header_name
    }

    /// Returns the HMAC secret key.
    #[must_use]
    pub const fn hmac_secret_key(&self) -> &HmacSecretKey {
        &self.hmac_secret_key
    }

    /// Returns the password policy.
    #[must_use]
    pub const fn password_policy(&self) -> &PasswordPolicy {
        &self.password_policy
    }

    /// Returns challenge lifetimes.
    #[must_use]
    pub const fn challenge_lifetimes(&self) -> &ChallengeLifetimes {
        &self.challenge_lifetimes
    }

    /// Returns rate limits.
    #[must_use]
    pub const fn rate_limits(&self) -> &AuthRateLimits {
        &self.rate_limits
    }

    /// Returns the auth email renderer.
    #[must_use]
    pub fn email_renderer(&self) -> &dyn AuthEmailRenderer {
        self.email_renderer.as_ref()
    }
}

impl fmt::Debug for HarborConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarborConfig")
            .field("public_base_url", &self.public_base_url)
            .field("cookie_defaults", &self.cookie_defaults)
            .field("csrf_header_name", &self.csrf_header_name)
            .field("hmac_secret_key", &"[REDACTED]")
            .field("password_policy", &self.password_policy)
            .field("challenge_lifetimes", &self.challenge_lifetimes)
            .field("rate_limits", &self.rate_limits)
            .field("email_renderer", &self.email_renderer)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HarborConfigBuilder {
    pub(crate) public_base_url: Option<PublicBaseUrl>,
    pub(crate) cookie_defaults: CookieDefaults,
    pub(crate) csrf_header_name: HeaderName,
    pub(crate) hmac_secret_key: Option<HmacSecretKey>,
    pub(crate) password_policy: PasswordPolicy,
    pub(crate) challenge_lifetimes: ChallengeLifetimes,
    pub(crate) rate_limits: AuthRateLimits,
    pub(crate) email_renderer: Option<Arc<dyn AuthEmailRenderer>>,
}

impl Default for HarborConfigBuilder {
    fn default() -> Self {
        Self {
            public_base_url: None,
            cookie_defaults: CookieDefaults::production(),
            csrf_header_name: HeaderName::new_unchecked("x-harbor-csrf"),
            hmac_secret_key: None,
            password_policy: PasswordPolicy::default(),
            challenge_lifetimes: ChallengeLifetimes::default(),
            rate_limits: AuthRateLimits::default(),
            email_renderer: None,
        }
    }
}

impl HarborConfigBuilder {
    pub(crate) fn finish(self) -> Result<HarborConfig, ConfigError> {
        self.cookie_defaults.validate()?;
        self.challenge_lifetimes.validate()?;
        self.rate_limits.validate()?;
        let public_base_url = self
            .public_base_url
            .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "public_base_url"))?;
        let email_renderer = self
            .email_renderer
            .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "email_renderer"))?;
        Ok(HarborConfig {
            public_base_url,
            cookie_defaults: self.cookie_defaults,
            csrf_header_name: self.csrf_header_name,
            hmac_secret_key: self
                .hmac_secret_key
                .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "hmac_key"))?,
            password_policy: self.password_policy,
            challenge_lifetimes: self.challenge_lifetimes,
            rate_limits: self.rate_limits,
            email_renderer,
        })
    }
}

/// Public base URL for auth links.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicBaseUrl(String);

impl PublicBaseUrl {
    /// Creates a validated public base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the URL is empty, too long, has a query or
    /// fragment, contains control characters, or is not HTTPS except for local
    /// development hosts.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let mut value = value.into();
        while value.ends_with('/') {
            value.pop();
        }
        if value.is_empty() {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::InvalidUrl,
                "base_url_empty",
            ));
        }
        if value.len() > MAX_BASE_URL_BYTES {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::InvalidUrl,
                "base_url_long",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::InvalidUrl,
                "base_url_control",
            ));
        }
        if value.contains('?') || value.contains('#') {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::InvalidUrl,
                "base_url_components",
            ));
        }
        if !is_allowed_public_base_url(&value) {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::InvalidUrl,
                "base_url_scheme",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the URL as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the host portion for display in default email templates.
    #[must_use]
    pub fn display_host(&self) -> &str {
        let without_scheme = self
            .0
            .strip_prefix("https://")
            .or_else(|| self.0.strip_prefix("http://"))
            .unwrap_or(self.0.as_str());
        without_scheme.split('/').next().unwrap_or(without_scheme)
    }
}

impl fmt::Debug for PublicBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PublicBaseUrl")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for PublicBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Auth challenge lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeLifetimes {
    /// Signup confirmation lifetime.
    pub signup_confirmation: UnixTimestampMicros,
    /// Email signin lifetime.
    pub email_signin: UnixTimestampMicros,
    /// Password reset lifetime.
    pub password_reset: UnixTimestampMicros,
}

impl Default for ChallengeLifetimes {
    fn default() -> Self {
        Self {
            signup_confirmation: UnixTimestampMicros::try_new(DEFAULT_SIGNUP_CHALLENGE_MICROS)
                .unwrap_or(UnixTimestampMicros::EPOCH),
            email_signin: UnixTimestampMicros::try_new(DEFAULT_EMAIL_SIGNIN_CHALLENGE_MICROS)
                .unwrap_or(UnixTimestampMicros::EPOCH),
            password_reset: UnixTimestampMicros::try_new(DEFAULT_PASSWORD_RESET_CHALLENGE_MICROS)
                .unwrap_or(UnixTimestampMicros::EPOCH),
        }
    }
}

impl ChallengeLifetimes {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.signup_confirmation.as_i64() <= 0
            || self.email_signin.as_i64() <= 0
            || self.password_reset.as_i64() <= 0
        {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "challenge_lifetime",
            ));
        }
        Ok(())
    }
}

/// Rate limits used by auth endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRateLimits {
    /// Signup attempts per window.
    pub signup: RetryBudget,
    /// Password signin attempts per window.
    pub password_signin: RetryBudget,
    /// Email challenge requests per window.
    pub email_challenge: RetryBudget,
    /// Password reset requests per window.
    pub password_reset: RetryBudget,
    /// Shared rate-limit window duration.
    pub window: UnixTimestampMicros,
}

impl Default for AuthRateLimits {
    fn default() -> Self {
        Self {
            signup: RetryBudget::try_new(5).unwrap_or(RetryBudget::ONE),
            password_signin: RetryBudget::try_new(10).unwrap_or(RetryBudget::ONE),
            email_challenge: RetryBudget::try_new(5).unwrap_or(RetryBudget::ONE),
            password_reset: RetryBudget::try_new(3).unwrap_or(RetryBudget::ONE),
            window: UnixTimestampMicros::try_new(DEFAULT_RATE_LIMIT_WINDOW_MICROS)
                .unwrap_or(UnixTimestampMicros::EPOCH),
        }
    }
}

impl AuthRateLimits {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.window.as_i64() <= 0 {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "rate_limit_window",
            ));
        }
        Ok(())
    }
}

fn is_allowed_public_base_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}
