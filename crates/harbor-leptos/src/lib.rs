//! Leptos integration helpers and components for Harbor.
//!
//! The crate starts with a framework-light configuration layer so server
//! function, cookie, CSRF, and component integrations share one validated
//! source of truth.

use core::fmt;

use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, ChallengeDelivery, ChallengePurpose, Clock,
    ConfigError, ConfigErrorCode, HmacSecretKey, PasswordBlocklist, PasswordPolicy, RedirectPath,
    RetryBudget, SecretGenerator, SecretHashPurpose, SecretToken, UnixTimestampMicros,
    constant_time_token_hash_eq, hash_secret_token, random_url_token,
};
use harbor_email::{
    AuthMailer, ChallengeEmailInput, EmailRecipient, SecretUrl, render_challenge_email,
};
use leptos::prelude::{CustomAttribute, ElementChild};

/// Version of the `harbor-leptos` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_BASE_URL_BYTES: usize = 2048;
const MAX_COOKIE_NAME_BYTES: usize = 64;
const MAX_HEADER_NAME_BYTES: usize = 64;
const DEFAULT_RATE_LIMIT_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;
const DEFAULT_SIGNUP_CHALLENGE_MICROS: i64 = 30 * 60 * 1_000_000;
const DEFAULT_EMAIL_SIGNIN_CHALLENGE_MICROS: i64 = 10 * 60 * 1_000_000;
const DEFAULT_PASSWORD_RESET_CHALLENGE_MICROS: i64 = 15 * 60 * 1_000_000;

/// Harbor application shell carrying validated config plus integration ports.
#[derive(Debug, Clone)]
pub struct Harbor<S, M> {
    store: S,
    mailer: M,
    config: HarborConfig,
}

impl Harbor<(), ()> {
    /// Starts a Harbor builder.
    #[must_use]
    pub fn builder() -> HarborBuilder<(), ()> {
        HarborBuilder::default()
    }
}

impl<S, M> Harbor<S, M> {
    /// Returns the configured store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Returns the configured mailer.
    #[must_use]
    pub const fn mailer(&self) -> &M {
        &self.mailer
    }

    /// Returns validated Harbor configuration.
    #[must_use]
    pub const fn config(&self) -> &HarborConfig {
        &self.config
    }
}

/// Harbor value stored in Leptos context.
#[derive(Debug, Clone)]
pub struct HarborLeptosContext<S, M> {
    harbor: Harbor<S, M>,
}

impl<S, M> HarborLeptosContext<S, M> {
    /// Creates a context wrapper.
    #[must_use]
    pub const fn new(harbor: Harbor<S, M>) -> Self {
        Self { harbor }
    }

    /// Returns the wrapped Harbor shell.
    #[must_use]
    pub const fn harbor(&self) -> &Harbor<S, M> {
        &self.harbor
    }

    /// Consumes the context wrapper.
    #[must_use]
    pub fn into_harbor(self) -> Harbor<S, M> {
        self.harbor
    }
}

/// Provides Harbor through Leptos context.
pub fn provide_harbor_context<S, M>(harbor: Harbor<S, M>)
where
    S: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    leptos::prelude::provide_context(HarborLeptosContext::new(harbor));
}

/// Attempts to load Harbor from Leptos context.
#[must_use]
pub fn use_harbor_context<S, M>() -> Option<HarborLeptosContext<S, M>>
where
    S: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    leptos::prelude::use_context::<HarborLeptosContext<S, M>>()
}

/// Loads Harbor from Leptos context.
///
/// # Panics
///
/// Panics if no [`HarborLeptosContext`] of the requested type exists in the
/// current Leptos owner.
#[must_use]
pub fn expect_harbor_context<S, M>() -> HarborLeptosContext<S, M>
where
    S: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    leptos::prelude::expect_context::<HarborLeptosContext<S, M>>()
}

/// Harbor builder.
#[derive(Debug, Clone)]
pub struct HarborBuilder<S, M> {
    store: Option<S>,
    mailer: Option<M>,
    config: HarborConfigBuilder,
}

impl Default for HarborBuilder<(), ()> {
    fn default() -> Self {
        Self {
            store: None,
            mailer: None,
            config: HarborConfigBuilder::default(),
        }
    }
}

impl<S, M> HarborBuilder<S, M> {
    /// Sets the auth store.
    #[must_use]
    pub fn with_store<NextStore>(self, store: NextStore) -> HarborBuilder<NextStore, M> {
        HarborBuilder {
            store: Some(store),
            mailer: self.mailer,
            config: self.config,
        }
    }

    /// Sets the auth mailer.
    #[must_use]
    pub fn with_mailer<NextMailer>(self, mailer: NextMailer) -> HarborBuilder<S, NextMailer> {
        HarborBuilder {
            store: self.store,
            mailer: Some(mailer),
            config: self.config,
        }
    }

    /// Sets the public base URL used for auth email links.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the URL is not an accepted public base URL.
    pub fn with_public_base_url(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.config.public_base_url = Some(PublicBaseUrl::try_new(value)?);
        Ok(self)
    }

    /// Sets cookie defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the cookie policy is invalid.
    pub fn with_cookie_defaults(mut self, value: CookieDefaults) -> Result<Self, ConfigError> {
        value.validate()?;
        self.config.cookie_defaults = value;
        Ok(self)
    }

    /// Sets the HMAC secret key used by token hashing services.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the key is too short or malformed.
    pub fn with_hmac_secret_key(mut self, value: impl Into<Vec<u8>>) -> Result<Self, ConfigError> {
        let key = HmacSecretKey::try_new(value.into())
            .map_err(|_error| ConfigError::with_detail(ConfigErrorCode::WeakSecret, "hmac_key"))?;
        self.config.hmac_secret_key = Some(key);
        Ok(self)
    }

    /// Sets password policy.
    pub fn with_password_policy(mut self, value: PasswordPolicy) -> Self {
        self.config.password_policy = value;
        self
    }

    /// Sets challenge lifetimes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a lifetime is not positive.
    pub fn with_challenge_lifetimes(
        mut self,
        value: ChallengeLifetimes,
    ) -> Result<Self, ConfigError> {
        value.validate()?;
        self.config.challenge_lifetimes = value;
        Ok(self)
    }

    /// Sets auth rate limits.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a rate-limit window is not positive.
    pub fn with_rate_limits(mut self, value: AuthRateLimits) -> Result<Self, ConfigError> {
        value.validate()?;
        self.config.rate_limits = value;
        Ok(self)
    }

    /// Finishes the builder.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a required port or configuration value is
    /// missing or invalid.
    pub fn finish(self) -> Result<Harbor<S, M>, ConfigError> {
        let store = self
            .store
            .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "store"))?;
        let mailer = self
            .mailer
            .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "mailer"))?;
        let config = self.config.finish()?;
        Ok(Harbor {
            store,
            mailer,
            config,
        })
    }
}

/// Validated Harbor configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct HarborConfig {
    public_base_url: PublicBaseUrl,
    cookie_defaults: CookieDefaults,
    csrf_header_name: HeaderName,
    hmac_secret_key: HmacSecretKey,
    password_policy: PasswordPolicy,
    challenge_lifetimes: ChallengeLifetimes,
    rate_limits: AuthRateLimits,
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
        }
    }
}

impl HarborConfigBuilder {
    fn finish(self) -> Result<HarborConfig, ConfigError> {
        self.cookie_defaults.validate()?;
        self.challenge_lifetimes.validate()?;
        self.rate_limits.validate()?;
        Ok(HarborConfig {
            public_base_url: self.public_base_url.ok_or_else(|| {
                ConfigError::with_detail(ConfigErrorCode::Missing, "public_base_url")
            })?,
            cookie_defaults: self.cookie_defaults,
            csrf_header_name: self.csrf_header_name,
            hmac_secret_key: self
                .hmac_secret_key
                .ok_or_else(|| ConfigError::with_detail(ConfigErrorCode::Missing, "hmac_key"))?,
            password_policy: self.password_policy,
            challenge_lifetimes: self.challenge_lifetimes,
            rate_limits: self.rate_limits,
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

/// Issues a new CSRF token.
///
/// # Errors
///
/// Returns [`AuthError`] when secure randomness fails.
pub fn issue_csrf_token(generator: &impl SecretGenerator) -> Result<SecretToken, AuthError> {
    random_url_token(generator)
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "csrf_token"))
}

/// Validates a CSRF double-submit cookie/header pair.
///
/// # Errors
///
/// Returns [`AuthError`] when either token is missing, malformed, or does not
/// match under Harbor's configured token hash key.
pub fn validate_csrf_tokens(
    config: &HarborConfig,
    cookie_token: Option<&str>,
    header_token: Option<&str>,
) -> Result<(), AuthError> {
    let cookie_token = parse_presented_csrf(cookie_token)?;
    let header_token = parse_presented_csrf(header_token)?;
    let cookie_hash = hash_secret_token(
        config.hmac_secret_key(),
        SecretHashPurpose::CsrfToken,
        &cookie_token,
    )
    .map_err(|_error| AuthError::with_detail(AuthErrorCode::Csrf, "csrf_cookie_hash"))?;
    let header_hash = hash_secret_token(
        config.hmac_secret_key(),
        SecretHashPurpose::CsrfToken,
        &header_token,
    )
    .map_err(|_error| AuthError::with_detail(AuthErrorCode::Csrf, "csrf_header_hash"))?;

    if constant_time_token_hash_eq(&cookie_hash, &header_hash) {
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
}

/// Generic auth action response for enumeration-resistant flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthActionResponse {
    /// Stable user-facing message.
    pub message: String,
}

/// Response that sets a session cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionActionResponse {
    /// Created session cookie header value.
    pub set_cookie: String,
    /// Optional redirect path.
    pub redirect_path: Option<RedirectPath>,
}

/// Signs up with password and sends a signup confirmation email.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, signup, challenge creation, mail
/// rendering, or delivery fails.
pub async fn signup_with_password<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::PasswordSignUpInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let signup = service.sign_up_with_password(input).await?;
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original.clone(),
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    send_challenge_email(mailer, config, challenge, "/auth/confirm-email").await?;
    Ok(AuthActionResponse {
        message: "Check your email to continue.".to_owned(),
    })
}

/// Signs in with password and returns a session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or signin fails.
pub async fn signin_with_password<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::PasswordSignInInput,
) -> Result<SessionActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    let signin = service.sign_in_with_password(input).await?;
    let set_cookie = build_session_cookie(config.cookie_defaults(), &signin.session_token, None)
        .map_err(AuthError::from)?;
    Ok(SessionActionResponse {
        set_cookie,
        redirect_path: signin.redirect_path,
    })
}

/// Requests an email signin challenge.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, challenge creation, rendering,
/// or delivery fails.
pub async fn request_email_signin<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    email: String,
    redirect_path: Option<RedirectPath>,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email,
            user_id: None,
            redirect_path,
        })
        .await?;
    send_challenge_email(mailer, config, challenge, "/auth/email-link").await?;
    Ok(AuthActionResponse {
        message: "Check your email to continue.".to_owned(),
    })
}

/// Verifies an email signin challenge and returns a session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or challenge signin fails.
pub async fn verify_email_code<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::EmailChallengeSignInInput,
) -> Result<SessionActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    let signin = service.sign_in_with_email_challenge(input).await?;
    let set_cookie = build_session_cookie(config.cookie_defaults(), &signin.session_token, None)
        .map_err(AuthError::from)?;
    Ok(SessionActionResponse {
        set_cookie,
        redirect_path: signin.redirect_path,
    })
}

/// Requests a password reset email.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, reset challenge creation, mail
/// rendering, or delivery fails.
pub async fn request_password_reset<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::RequestPasswordResetInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let reset = service.request_password_reset(input).await?;
    if let Some(challenge) = reset.challenge {
        send_challenge_email(mailer, config, challenge, "/auth/reset-password").await?;
    }
    Ok(AuthActionResponse {
        message: "If the address is eligible, a reset email has been sent.".to_owned(),
    })
}

/// Resets a password.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or password reset fails.
pub async fn reset_password<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::ResetPasswordInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    service.reset_password(input).await?;
    Ok(AuthActionResponse {
        message: "Your password has been reset.".to_owned(),
    })
}

/// Signs out from the current session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or signout fails.
pub async fn sign_out<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
) -> Result<String, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    if let Some(cookie_header) = csrf.cookie_header.as_deref()
        && let Some(session_token) = parse_cookie_value(
            cookie_header,
            config.cookie_defaults().session_cookie_name(),
        )
    {
        let token = SecretToken::try_new(session_token)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        service.sign_out(&token).await?;
    }
    Ok(build_delete_session_cookie(config.cookie_defaults()))
}

/// Loads the current session from the request cookie header.
///
/// # Errors
///
/// Returns [`AuthError`] when session token hashing or storage fails.
pub async fn current_session<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    cookie_header: Option<&str>,
) -> Result<Option<harbor_core::CurrentSession>, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let Some(cookie_header) = cookie_header else {
        return Ok(None);
    };
    let Some(session_token) = parse_cookie_value(
        cookie_header,
        config.cookie_defaults().session_cookie_name(),
    ) else {
        return Ok(None);
    };
    let token = SecretToken::try_new(session_token)
        .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
    service.current_session(&token).await
}

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

fn validate_csrf_request(config: &HarborConfig, csrf: &CsrfRequest) -> Result<(), AuthError> {
    validate_csrf_from_headers(
        config,
        csrf.cookie_header.as_deref(),
        csrf.csrf_header.as_deref(),
    )
}

async fn send_challenge_email<M: AuthMailer>(
    mailer: &M,
    config: &HarborConfig,
    challenge: harbor_core::EmailChallengeOutput,
    route: &str,
) -> Result<(), AuthError> {
    let action_url = match challenge.challenge.delivery {
        ChallengeDelivery::MagicLink | ChallengeDelivery::Both => {
            Some(challenge_action_url(config, route, &challenge)?)
        }
        ChallengeDelivery::OtpCode => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let otp_code = match challenge.challenge.delivery {
        ChallengeDelivery::OtpCode | ChallengeDelivery::Both => Some(challenge.secret.clone()),
        ChallengeDelivery::MagicLink => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let recipient = EmailRecipient::parse(challenge.challenge.email_canonical.as_str())?;
    let email = render_challenge_email(ChallengeEmailInput {
        purpose: challenge.challenge.purpose,
        delivery: challenge.challenge.delivery,
        to: recipient,
        challenge_id: challenge.challenge.id,
        action_url,
        otp_code,
    })?;
    mailer
        .send_auth_email(email)
        .await
        .map_err(AuthError::from)?;
    Ok(())
}

fn challenge_action_url(
    config: &HarborConfig,
    route: &str,
    challenge: &harbor_core::EmailChallengeOutput,
) -> Result<SecretUrl, AuthError> {
    let mut url = format!(
        "{}{}?challenge={}&token={}",
        config.public_base_url().as_str(),
        route,
        challenge.challenge.id.as_str(),
        challenge.secret.expose_secret()
    );
    if let Some(redirect_path) = challenge.challenge.redirect_path.as_ref() {
        url.push_str("&redirect=");
        url.push_str(percent_encode_query(redirect_path.as_str()).as_str());
    }
    SecretUrl::try_new(url).map_err(AuthError::from)
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

fn parse_presented_csrf(value: Option<&str>) -> Result<SecretToken, AuthError> {
    let value = value.ok_or_else(|| AuthError::new(AuthErrorCode::Csrf))?;
    SecretToken::try_new(value.to_owned()).map_err(|_error| AuthError::new(AuthErrorCode::Csrf))
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

/// Email/password signup form.
#[leptos::prelude::component]
pub fn SignupForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/signup" data-harbor-form="signup">
            <label for="harbor-signup-email">"Email"</label>
            <input id="harbor-signup-email" name="email" type="email" autocomplete="email" required />
            <label for="harbor-signup-password">"Password"</label>
            <input id="harbor-signup-password" name="password" type="password" autocomplete="new-password" required />
            <button type="submit">"Sign up"</button>
        </form>
    }
}

/// Email/password signin form.
#[leptos::prelude::component]
pub fn SigninForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/signin" data-harbor-form="signin">
            <label for="harbor-signin-email">"Email"</label>
            <input id="harbor-signin-email" name="email" type="email" autocomplete="email" required />
            <label for="harbor-signin-password">"Password"</label>
            <input id="harbor-signin-password" name="password" type="password" autocomplete="current-password" required />
            <button type="submit">"Sign in"</button>
        </form>
    }
}

/// Email OTP/link request form.
#[leptos::prelude::component]
pub fn EmailCodeForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/email" data-harbor-form="email-code">
            <label for="harbor-email-code-email">"Email"</label>
            <input id="harbor-email-code-email" name="email" type="email" autocomplete="email" required />
            <button type="submit">"Email me a sign-in link"</button>
        </form>
    }
}

/// Forgot-password request form.
#[leptos::prelude::component]
pub fn ForgotPasswordForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/forgot-password" data-harbor-form="forgot-password">
            <label for="harbor-forgot-email">"Email"</label>
            <input id="harbor-forgot-email" name="email" type="email" autocomplete="email" required />
            <button type="submit">"Reset password"</button>
        </form>
    }
}

/// Password reset form.
#[leptos::prelude::component]
pub fn ResetPasswordForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/reset-password" data-harbor-form="reset-password">
            <input name="challenge_id" type="hidden" />
            <input name="token" type="hidden" />
            <label for="harbor-reset-password">"New password"</label>
            <input id="harbor-reset-password" name="password" type="password" autocomplete="new-password" required />
            <button type="submit">"Save password"</button>
        </form>
    }
}

#[cfg(test)]
mod tests {
    use harbor_core::{AuthErrorCode, SecretToken};
    use harbor_email::RecordingMailer;
    use harbor_test_support::DeterministicSecretGenerator;
    use leptos::prelude::Owner;

    use super::{
        CookieDefaults, CookieName, Harbor, PublicBaseUrl, SameSite, UnixTimestampMicros,
        build_csrf_cookie, build_delete_session_cookie, build_session_cookie, parse_cookie_value,
        provide_harbor_context, use_harbor_context, validate_csrf_from_headers,
        validate_csrf_tokens,
    };

    #[test]
    fn builder_validates_required_configuration() -> Result<(), Box<dyn std::error::Error>> {
        let missing = Harbor::builder().finish();
        assert!(missing.is_err());

        let harbor = Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("https://issuecertificate.com/")?
            .with_hmac_secret_key(vec![7; 32])?
            .finish()?;

        assert_eq!(
            harbor.config().public_base_url().as_str(),
            "https://issuecertificate.com"
        );
        assert_eq!(
            harbor
                .config()
                .cookie_defaults()
                .session_cookie_name()
                .as_str(),
            "__Host-harbor-session"
        );
        assert!(!format!("{:?}", harbor.config()).contains("7, 7"));
        Ok(())
    }

    #[test]
    fn public_base_url_requires_https_except_local_development() {
        assert!(PublicBaseUrl::try_new("https://issuecertificate.com").is_ok());
        assert!(PublicBaseUrl::try_new("http://localhost:3000").is_ok());
        assert!(PublicBaseUrl::try_new("http://127.0.0.1:3000").is_ok());
        assert!(PublicBaseUrl::try_new("http://example.com").is_err());
        assert!(PublicBaseUrl::try_new("https://example.com?x=1").is_err());
    }

    #[test]
    fn cookie_policy_rejects_insecure_cross_site_and_bad_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let insecure_cross_site = CookieDefaults::development().with_same_site(SameSite::None);
        let builder = Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![7; 32])?;

        assert!(builder.with_cookie_defaults(insecure_cross_site).is_err());
        assert!(CookieName::try_new("bad name").is_err());
        Ok(())
    }

    #[test]
    fn custom_lifetimes_reject_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let lifetimes = super::ChallengeLifetimes {
            signup_confirmation: UnixTimestampMicros::EPOCH,
            email_signin: UnixTimestampMicros::try_new(1)?,
            password_reset: UnixTimestampMicros::try_new(1)?,
        };
        let builder = Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![7; 32])?;

        assert!(builder.with_challenge_lifetimes(lifetimes).is_err());
        Ok(())
    }

    #[test]
    fn leptos_context_round_trips_harbor_shell() -> Result<(), Box<dyn std::error::Error>> {
        let harbor = Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![7; 32])?
            .finish()?;
        let owner = Owner::new();

        owner.with(|| {
            provide_harbor_context(harbor.clone());
            let loaded = use_harbor_context::<&'static str, RecordingMailer>();
            match loaded {
                Some(context) => {
                    assert_eq!(
                        context.harbor().config().public_base_url().as_str(),
                        "http://localhost:3000"
                    );
                    Ok(())
                }
                None => Err("harbor context should be available".into()),
            }
        })
    }

    #[test]
    fn cookie_helpers_build_parse_and_delete_headers() -> Result<(), Box<dyn std::error::Error>> {
        let defaults = CookieDefaults::production();
        let session =
            build_session_cookie(&defaults, &SecretToken::try_new("sessiontoken")?, Some(60))?;
        let csrf = build_csrf_cookie(&defaults, &SecretToken::try_new("csrftoken")?, None)?;
        let parsed = parse_cookie_value(
            "other=1; __Host-harbor-session=sessiontoken; harbor_csrf=old",
            defaults.session_cookie_name(),
        );
        let delete = build_delete_session_cookie(&defaults);

        assert!(session.contains("__Host-harbor-session=sessiontoken"));
        assert!(session.contains("Max-Age=60"));
        assert!(session.contains("Secure"));
        assert!(session.contains("HttpOnly"));
        assert!(csrf.contains("__Host-harbor-csrf=csrftoken"));
        assert!(!csrf.contains("HttpOnly"));
        assert_eq!(parsed, Some("sessiontoken".to_owned()));
        assert!(delete.contains("Max-Age=0"));
        Ok(())
    }

    #[test]
    fn csrf_tokens_validate_through_cookie_and_header() -> Result<(), Box<dyn std::error::Error>> {
        let harbor = Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![7; 32])?
            .finish()?;
        let token = super::issue_csrf_token(&DeterministicSecretGenerator::new())?;
        let csrf_cookie = build_csrf_cookie(harbor.config().cookie_defaults(), &token, None)?;
        let cookie_header = match csrf_cookie.split(';').next() {
            Some(value) => value,
            None => return Err("cookie header should have a name-value pair".into()),
        };

        validate_csrf_tokens(
            harbor.config(),
            Some(token.expose_secret()),
            Some(token.expose_secret()),
        )?;
        validate_csrf_from_headers(
            harbor.config(),
            Some(cookie_header),
            Some(token.expose_secret()),
        )?;

        let mismatch =
            validate_csrf_tokens(harbor.config(), Some(token.expose_secret()), Some("wrong"));
        let mismatch = match mismatch {
            Ok(()) => return Err("csrf mismatch should fail".into()),
            Err(error) => error,
        };
        assert_eq!(mismatch.code(), AuthErrorCode::Csrf);

        let missing = validate_csrf_tokens(harbor.config(), None, Some(token.expose_secret()));
        let missing = match missing {
            Ok(()) => return Err("missing csrf cookie should fail".into()),
            Err(error) => error,
        };
        assert_eq!(missing.code(), AuthErrorCode::Csrf);
        Ok(())
    }
}
