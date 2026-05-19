//! Leptos integration helpers and components for Harbor.
//!
//! The crate starts with a framework-light configuration layer so server
//! function, cookie, CSRF, and component integrations share one validated
//! source of truth.

use core::fmt;
use std::sync::Arc;

use harbor_core::{
    AuthError, AuthErrorCode, ConfigError, ConfigErrorCode, HmacSecretKey, PasswordPolicy,
    RetryBudget, SecretGenerator, SecretHashPurpose, SecretToken, UnixTimestampMicros,
    constant_time_token_hash_eq, hash_secret, random_url_token,
};
use harbor_email::AuthEmailRenderer;

/// Version of the `harbor-leptos` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod app;
mod components;
mod links;
mod workflow;
pub use app::{
    Harbor, HarborBuilder, HarborLeptosContext, expect_harbor_context, provide_harbor_context,
    use_harbor_context,
};
pub use components::{
    Authenticated, EmailCodeForm, ForgotPasswordForm, ResetPasswordForm, SignOutForm, SigninForm,
    SignupForm, Unauthenticated,
};
pub use links::{
    AuthLinkQuery, LinkRouteResponse, handle_confirm_email_link, handle_email_link_signin,
    handle_reset_password_link,
};
pub use workflow::{
    AuthActionResponse, EmailCodeActionResponse, SessionActionResponse, current_session,
    request_email_code_signin, request_email_signin, request_password_reset, reset_password,
    sign_out, signin_with_password, signup_with_password, verify_email_code,
};

const MAX_BASE_URL_BYTES: usize = 2048;
const MAX_COOKIE_NAME_BYTES: usize = 64;
const MAX_HEADER_NAME_BYTES: usize = 64;
const DEFAULT_RATE_LIMIT_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;
const DEFAULT_SIGNUP_CHALLENGE_MICROS: i64 = 30 * 60 * 1_000_000;
const DEFAULT_EMAIL_SIGNIN_CHALLENGE_MICROS: i64 = 10 * 60 * 1_000_000;
const DEFAULT_PASSWORD_RESET_CHALLENGE_MICROS: i64 = 15 * 60 * 1_000_000;
const CSRF_TOKEN_SEPARATOR: char = '.';

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
struct HarborConfigBuilder {
    public_base_url: Option<PublicBaseUrl>,
    cookie_defaults: CookieDefaults,
    csrf_header_name: HeaderName,
    hmac_secret_key: Option<HmacSecretKey>,
    password_policy: PasswordPolicy,
    challenge_lifetimes: ChallengeLifetimes,
    rate_limits: AuthRateLimits,
    email_renderer: Option<Arc<dyn AuthEmailRenderer>>,
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
    fn finish(self) -> Result<HarborConfig, ConfigError> {
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

/// Cookie SameSite policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Same-site and top-level navigation cookies.
    Lax,
    /// Same-site requests only.
    Strict,
    /// Cross-site cookies. Requires `Secure`.
    None,
}

/// Cookie defaults used by Harbor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieDefaults {
    session_cookie_name: CookieName,
    csrf_cookie_name: CookieName,
    path: String,
    secure: bool,
    session_http_only: bool,
    csrf_http_only: bool,
    same_site: SameSite,
}

impl CookieDefaults {
    /// Production cookie defaults.
    #[must_use]
    pub fn production() -> Self {
        Self {
            session_cookie_name: CookieName::new_unchecked("__Host-harbor-session"),
            csrf_cookie_name: CookieName::new_unchecked("__Host-harbor-csrf"),
            path: "/".to_owned(),
            secure: true,
            session_http_only: true,
            csrf_http_only: false,
            same_site: SameSite::Lax,
        }
    }

    /// Local development cookie defaults.
    #[must_use]
    pub fn development() -> Self {
        Self {
            secure: false,
            session_cookie_name: CookieName::new_unchecked("harbor_session"),
            csrf_cookie_name: CookieName::new_unchecked("harbor_csrf"),
            ..Self::production()
        }
    }

    /// Returns the session cookie name.
    #[must_use]
    pub const fn session_cookie_name(&self) -> &CookieName {
        &self.session_cookie_name
    }

    /// Returns the CSRF cookie name.
    #[must_use]
    pub const fn csrf_cookie_name(&self) -> &CookieName {
        &self.csrf_cookie_name
    }

    /// Returns the cookie path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether cookies should use `Secure`.
    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }

    /// Returns whether the session cookie should use `HttpOnly`.
    #[must_use]
    pub const fn session_http_only(&self) -> bool {
        self.session_http_only
    }

    /// Returns whether the CSRF cookie should use `HttpOnly`.
    #[must_use]
    pub const fn csrf_http_only(&self) -> bool {
        self.csrf_http_only
    }

    /// Returns SameSite policy.
    #[must_use]
    pub const fn same_site(&self) -> SameSite {
        self.same_site
    }

    /// Sets SameSite policy.
    #[must_use]
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.session_cookie_name.validate()?;
        self.csrf_cookie_name.validate()?;
        if self.path != "/" {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "cookie_path",
            ));
        }
        if self.same_site == SameSite::None && !self.secure {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "samesite_none_secure",
            ));
        }
        if !self.session_http_only || self.csrf_http_only {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "cookie_http_only",
            ));
        }
        Ok(())
    }
}

/// Builds a `Set-Cookie` value for the Harbor session cookie.
///
/// # Errors
///
/// Returns [`ConfigError`] when the token is not safe for cookie transport or
/// the max-age is negative.
pub fn build_session_cookie(
    defaults: &CookieDefaults,
    session_token: &SecretToken,
    max_age_seconds: Option<i64>,
) -> Result<String, ConfigError> {
    build_cookie_header(
        defaults.session_cookie_name(),
        session_token.expose_secret(),
        defaults,
        defaults.session_http_only(),
        max_age_seconds,
    )
}

/// Builds a deletion `Set-Cookie` value for the Harbor session cookie.
#[must_use]
pub fn build_delete_session_cookie(defaults: &CookieDefaults) -> String {
    build_delete_cookie_header(
        defaults.session_cookie_name(),
        defaults,
        defaults.session_http_only(),
    )
}

/// Builds a `Set-Cookie` value for the Harbor CSRF cookie.
///
/// # Errors
///
/// Returns [`ConfigError`] when the token is not safe for cookie transport or
/// the max-age is negative.
pub fn build_csrf_cookie(
    defaults: &CookieDefaults,
    csrf_token: &SecretToken,
    max_age_seconds: Option<i64>,
) -> Result<String, ConfigError> {
    build_cookie_header(
        defaults.csrf_cookie_name(),
        csrf_token.expose_secret(),
        defaults,
        defaults.csrf_http_only(),
        max_age_seconds,
    )
}

/// Builds a deletion `Set-Cookie` value for the Harbor CSRF cookie.
#[must_use]
pub fn build_delete_csrf_cookie(defaults: &CookieDefaults) -> String {
    build_delete_cookie_header(
        defaults.csrf_cookie_name(),
        defaults,
        defaults.csrf_http_only(),
    )
}

/// Parses a cookie value from a `Cookie` request header.
#[must_use]
pub fn parse_cookie_value(cookie_header: &str, name: &CookieName) -> Option<String> {
    cookie_header.split(';').find_map(|part| {
        let (candidate_name, value) = part.trim().split_once('=')?;
        if candidate_name == name.as_str() {
            Some(value.to_owned())
        } else {
            None
        }
    })
}

/// Issues a new signed CSRF token.
///
/// # Errors
///
/// Returns [`AuthError`] when secure randomness or token signing fails.
pub fn issue_csrf_token(
    config: &HarborConfig,
    generator: &impl SecretGenerator,
) -> Result<SecretToken, AuthError> {
    let nonce = random_url_token(generator)
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "csrf_token"))?;
    let signature = hash_secret(
        config.hmac_secret_key(),
        SecretHashPurpose::CsrfToken,
        nonce.expose_secret().as_bytes(),
    )
    .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "csrf_signature"))?;
    SecretToken::try_new(format!(
        "{}{}{}",
        nonce.expose_secret(),
        CSRF_TOKEN_SEPARATOR,
        lower_hex(signature.as_bytes())
    ))
    .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "csrf_token_format"))
}

/// Validates a CSRF double-submit cookie/header pair.
///
/// # Errors
///
/// Returns [`AuthError`] when either token is missing, malformed, or does not
/// carry a valid signature under Harbor's configured token hash key.
pub fn validate_csrf_tokens(
    config: &HarborConfig,
    cookie_token: Option<&str>,
    header_token: Option<&str>,
) -> Result<(), AuthError> {
    let cookie_token = parse_presented_csrf(config, cookie_token)?;
    let header_token = parse_presented_csrf(config, header_token)?;

    if constant_time_token_hash_eq(&cookie_token, &header_token) {
        Ok(())
    } else {
        Err(AuthError::new(AuthErrorCode::Csrf))
    }
}

/// Parses and validates a CSRF token from a request cookie header.
///
/// # Errors
///
/// Returns [`AuthError`] when the cookie is missing or the CSRF pair is invalid.
pub fn validate_csrf_from_headers(
    config: &HarborConfig,
    cookie_header: Option<&str>,
    csrf_header: Option<&str>,
) -> Result<(), AuthError> {
    let cookie_token = cookie_header
        .and_then(|header| parse_cookie_value(header, config.cookie_defaults().csrf_cookie_name()));
    validate_csrf_tokens(config, cookie_token.as_deref(), csrf_header)
}

/// CSRF values extracted from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfRequest {
    /// Raw `Cookie` request header.
    pub cookie_header: Option<String>,
    /// Raw configured CSRF request header.
    pub csrf_header: Option<String>,
    /// Optional non-secret request fingerprint used for rate limiting.
    ///
    /// Applications can populate this from trusted edge metadata such as a
    /// canonical client IP or IP/user-agent tuple. Harbor HMAC-hashes the value
    /// before persistence.
    pub rate_limit_key: Option<String>,
}

#[cfg(feature = "axum")]
pub mod axum;

/// Validated cookie name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CookieName(String);

impl CookieName {
    /// Creates a validated cookie name.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the cookie name is empty, too long, or
    /// contains characters outside Harbor's conservative cookie-name alphabet.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        let name = Self(value);
        name.validate()?;
        Ok(name)
    }

    fn new_unchecked(value: &str) -> Self {
        Self(value.to_owned())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.0.is_empty() {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "cookie_name_empty",
            ));
        }
        if self.0.len() > MAX_COOKIE_NAME_BYTES {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "cookie_name_long",
            ));
        }
        if !self
            .0
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "cookie_name_chars",
            ));
        }
        Ok(())
    }

    /// Returns the cookie name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CookieName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CookieName").field(&self.0).finish()
    }
}

/// Validated HTTP header name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// Creates a validated header name.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the header name is empty, too long, or
    /// contains invalid characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        let name = Self(value);
        name.validate()?;
        Ok(name)
    }

    fn new_unchecked(value: &str) -> Self {
        Self(value.to_owned())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.0.is_empty() {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "header_name_empty",
            ));
        }
        if self.0.len() > MAX_HEADER_NAME_BYTES {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "header_name_long",
            ));
        }
        if !self
            .0
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-'))
        {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "header_name_chars",
            ));
        }
        Ok(())
    }

    /// Returns the header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("HeaderName").field(&self.0).finish()
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
    fn validate(&self) -> Result<(), ConfigError> {
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
    fn validate(&self) -> Result<(), ConfigError> {
        if self.window.as_i64() <= 0 {
            return Err(ConfigError::with_detail(
                ConfigErrorCode::Invalid,
                "rate_limit_window",
            ));
        }
        Ok(())
    }
}

fn percent_encode_query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + (value - 10)),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn build_cookie_header(
    name: &CookieName,
    value: &str,
    defaults: &CookieDefaults,
    http_only: bool,
    max_age_seconds: Option<i64>,
) -> Result<String, ConfigError> {
    validate_cookie_value(value)?;
    if let Some(max_age_seconds) = max_age_seconds
        && max_age_seconds < 0
    {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "cookie_max_age",
        ));
    }

    let mut header = format!("{}={}; Path={}", name.as_str(), value, defaults.path());
    if let Some(max_age_seconds) = max_age_seconds {
        header.push_str("; Max-Age=");
        header.push_str(max_age_seconds.to_string().as_str());
    }
    header.push_str("; SameSite=");
    header.push_str(same_site_value(defaults.same_site()));
    if defaults.secure() {
        header.push_str("; Secure");
    }
    if http_only {
        header.push_str("; HttpOnly");
    }
    Ok(header)
}

fn build_delete_cookie_header(
    name: &CookieName,
    defaults: &CookieDefaults,
    http_only: bool,
) -> String {
    let mut header = format!("{}=; Path={}; Max-Age=0", name.as_str(), defaults.path());
    header.push_str("; SameSite=");
    header.push_str(same_site_value(defaults.same_site()));
    if defaults.secure() {
        header.push_str("; Secure");
    }
    if http_only {
        header.push_str("; HttpOnly");
    }
    header
}

fn validate_cookie_value(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "cookie_value_empty",
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, ';' | ','))
    {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "cookie_value_chars",
        ));
    }
    Ok(())
}

fn parse_presented_csrf(
    config: &HarborConfig,
    value: Option<&str>,
) -> Result<harbor_core::TokenHash, AuthError> {
    let value = value.ok_or_else(|| AuthError::new(AuthErrorCode::Csrf))?;
    let (nonce, signature) = value
        .split_once(CSRF_TOKEN_SEPARATOR)
        .ok_or_else(|| AuthError::new(AuthErrorCode::Csrf))?;
    if signature.contains(CSRF_TOKEN_SEPARATOR) {
        return Err(AuthError::new(AuthErrorCode::Csrf));
    }
    let nonce = SecretToken::try_new(nonce.to_owned())
        .map_err(|_error| AuthError::new(AuthErrorCode::Csrf))?;
    let expected = hash_secret(
        config.hmac_secret_key(),
        SecretHashPurpose::CsrfToken,
        nonce.expose_secret().as_bytes(),
    )
    .map_err(|_error| AuthError::with_detail(AuthErrorCode::Csrf, "csrf_signature"))?;
    let presented = harbor_core::TokenHash::try_new(decode_hex(signature)?)
        .map_err(|_error| AuthError::new(AuthErrorCode::Csrf))?;
    if constant_time_token_hash_eq(&expected, &presented) {
        Ok(presented)
    } else {
        Err(AuthError::new(AuthErrorCode::Csrf))
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AuthError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(AuthError::new(AuthErrorCode::Csrf));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or_else(|| AuthError::new(AuthErrorCode::Csrf))?;
        let low = hex_value(pair[1]).ok_or_else(|| AuthError::new(AuthErrorCode::Csrf))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn same_site_value(same_site: SameSite) -> &'static str {
    match same_site {
        SameSite::Lax => "Lax",
        SameSite::Strict => "Strict",
        SameSite::None => "None",
    }
}

fn is_allowed_public_base_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

#[cfg(test)]
mod tests;
