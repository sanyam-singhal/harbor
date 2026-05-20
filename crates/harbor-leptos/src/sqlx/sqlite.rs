//! SQLite setup helpers for Leptos applications.

use core::fmt;
use std::sync::Arc;

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, ConfigError, ConfigErrorCode, HmacSecretKey,
    MailError, PasswordPolicy, StoreError, SystemClock, SystemSecretGenerator,
};
use harbor_email::{AuthEmailRenderer, ConfiguredAuthMailer};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

use crate::{AuthApi, AuthFlowConfig, AuthRouteConfig, CookieDefaults, Harbor, HarborConfig};

/// Default auth service used by the SQLite Leptos integration.
pub type SqliteHarborService = AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>;

/// Fully initialized Harbor auth state for SQLite-backed Leptos applications.
#[derive(Clone)]
pub struct SqliteHarbor<M> {
    harbor: Harbor<SqliteAuthStore, M>,
    service: SqliteHarborService,
    flow_config: AuthFlowConfig,
    route_config: AuthRouteConfig,
}

impl<M: fmt::Debug> fmt::Debug for SqliteHarbor<M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteHarbor")
            .field("harbor", &self.harbor)
            .field("service", &"AuthService")
            .field("flow_config", &self.flow_config)
            .field("route_config", &self.route_config)
            .finish()
    }
}

impl SqliteHarbor<()> {
    /// Starts the SQLite Harbor setup builder.
    #[must_use]
    pub fn builder() -> SqliteHarborBuilder<()> {
        SqliteHarborBuilder::default()
    }
}

impl<M> SqliteHarbor<M> {
    /// Returns the configured Harbor Leptos shell.
    #[must_use]
    pub const fn harbor(&self) -> &Harbor<SqliteAuthStore, M> {
        &self.harbor
    }

    /// Returns the configured auth service.
    #[must_use]
    pub const fn service(&self) -> &SqliteHarborService {
        &self.service
    }

    /// Returns the validated Harbor configuration.
    #[must_use]
    pub const fn config(&self) -> &HarborConfig {
        self.harbor.config()
    }

    /// Returns the configured SQLite store.
    #[must_use]
    pub const fn store(&self) -> &SqliteAuthStore {
        self.harbor.store()
    }

    /// Returns the configured mailer.
    #[must_use]
    pub const fn mailer(&self) -> &M {
        self.harbor.mailer()
    }

    /// Returns flow configuration.
    #[must_use]
    pub const fn flow_config(&self) -> &AuthFlowConfig {
        &self.flow_config
    }

    /// Returns route configuration.
    #[must_use]
    pub const fn route_config(&self) -> &AuthRouteConfig {
        &self.route_config
    }

    /// Returns high-level auth API methods.
    #[must_use]
    pub const fn api(
        &self,
    ) -> AuthApi<
        '_,
        SqliteAuthStore,
        M,
        SystemClock,
        SystemSecretGenerator,
        harbor_core::CommonPasswordBlocklist,
    > {
        AuthApi::new_runtime_parts(
            &self.harbor,
            &self.service,
            &self.flow_config,
            &self.route_config,
        )
    }

    /// Builds Harbor's Axum auth route bundle for this SQLite runtime.
    #[cfg(feature = "axum")]
    #[must_use]
    pub fn axum_router(&self) -> ::axum::Router
    where
        M: harbor_email::AuthMailer,
    {
        crate::axum::auth_router(crate::axum::HarborAuthAxumState::new(
            self.harbor.clone(),
            self.service.clone(),
            self.flow_config.clone(),
            self.route_config.clone(),
        ))
    }
}

impl SqliteHarbor<ConfiguredAuthMailer> {
    /// Builds SQLite-backed Harbor auth from standard environment variables
    /// and an app-owned Rust email renderer.
    ///
    /// Reads database, public URL, HMAC, and email delivery settings from the
    /// environment. The supplied renderer owns subject/text/HTML generation.
    ///
    /// # Errors
    ///
    /// Returns [`HarborSetupError`] when environment, mailer, database, or
    /// Harbor config setup fails.
    pub async fn from_env_with_email_renderer(
        renderer: impl AuthEmailRenderer,
    ) -> Result<Self, HarborSetupError> {
        SqliteHarborBuilder::from_env()?
            .with_email_renderer(renderer)
            .with_mailer(ConfiguredAuthMailer::from_env()?)
            .connect()
            .await
    }
}

/// Builder for SQLite-backed Harbor auth in Leptos applications.
#[derive(Debug, Clone)]
pub struct SqliteHarborBuilder<M> {
    database_url: Option<String>,
    sqlite_options: SqliteStoreOptions,
    mailer: Option<M>,
    public_base_url: Option<String>,
    cookie_defaults: Option<CookieDefaults>,
    hmac_key: Option<Vec<u8>>,
    password_policy: PasswordPolicy,
    argon2_params: Argon2Params,
    email_renderer: Option<SharedEmailRenderer>,
    flow_config: AuthFlowConfig,
    route_config: AuthRouteConfig,
}

impl Default for SqliteHarborBuilder<()> {
    fn default() -> Self {
        Self {
            database_url: None,
            sqlite_options: SqliteStoreOptions::default(),
            mailer: None,
            public_base_url: None,
            cookie_defaults: None,
            hmac_key: None,
            password_policy: PasswordPolicy::default(),
            argon2_params: Argon2Params::owasp_minimum(),
            email_renderer: None,
            flow_config: AuthFlowConfig::default(),
            route_config: AuthRouteConfig::default(),
        }
    }
}

impl SqliteHarborBuilder<()> {
    /// Creates a builder from Harbor's standard environment variables.
    ///
    /// Reads `HARBOR_DATABASE_URL`, `HARBOR_PUBLIC_BASE_URL`,
    /// `HARBOR_HMAC_KEY`, `HARBOR_PRODUCT_NAME`, and optionally
    /// `HARBOR_EMAIL_SITE_NAME`.
    ///
    /// # Errors
    ///
    /// Returns [`HarborSetupError`] when a required variable is missing or
    /// values fail validation.
    pub fn from_env() -> Result<Self, HarborSetupError> {
        let public_base_url = required_env("HARBOR_PUBLIC_BASE_URL")?;
        let product_name = required_env("HARBOR_PRODUCT_NAME")?;
        let public_url = crate::PublicBaseUrl::try_new(public_base_url.clone())?;
        let site_name = optional_env("HARBOR_EMAIL_SITE_NAME")
            .unwrap_or_else(|| public_url.display_host().to_owned());

        Self::default()
            .with_database_url(required_env("HARBOR_DATABASE_URL")?)
            .with_public_base_url(public_base_url)
            .with_hmac_secret_key(required_env("HARBOR_HMAC_KEY")?.into_bytes())
            .with_default_email_renderer(product_name, site_name)
    }
}

impl<M> SqliteHarborBuilder<M> {
    /// Sets the SQLite database URL.
    #[must_use]
    pub fn with_database_url(mut self, value: impl Into<String>) -> Self {
        self.database_url = Some(value.into());
        self
    }

    /// Sets SQLite connection options.
    #[must_use]
    pub fn with_sqlite_options(mut self, value: SqliteStoreOptions) -> Self {
        self.sqlite_options = value;
        self
    }

    /// Sets the mailer used for auth email delivery.
    #[must_use]
    pub fn with_mailer<NextMailer>(self, mailer: NextMailer) -> SqliteHarborBuilder<NextMailer> {
        SqliteHarborBuilder {
            database_url: self.database_url,
            sqlite_options: self.sqlite_options,
            mailer: Some(mailer),
            public_base_url: self.public_base_url,
            cookie_defaults: self.cookie_defaults,
            hmac_key: self.hmac_key,
            password_policy: self.password_policy,
            argon2_params: self.argon2_params,
            email_renderer: self.email_renderer,
            flow_config: self.flow_config,
            route_config: self.route_config,
        }
    }

    /// Sets the public base URL used in auth links.
    #[must_use]
    pub fn with_public_base_url(mut self, value: impl Into<String>) -> Self {
        self.public_base_url = Some(value.into());
        self
    }

    /// Sets cookie defaults. When omitted, Harbor chooses production cookies
    /// for HTTPS base URLs and development cookies for local HTTP URLs.
    #[must_use]
    pub fn with_cookie_defaults(mut self, value: CookieDefaults) -> Self {
        self.cookie_defaults = Some(value);
        self
    }

    /// Sets the HMAC secret key bytes used for token hashing.
    #[must_use]
    pub fn with_hmac_secret_key(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.hmac_key = Some(value.into());
        self
    }

    /// Sets the password policy.
    #[must_use]
    pub fn with_password_policy(mut self, value: PasswordPolicy) -> Self {
        self.password_policy = value;
        self
    }

    /// Sets the Argon2 parameters for password hashing.
    #[must_use]
    pub fn with_argon2_params(mut self, value: Argon2Params) -> Self {
        self.argon2_params = value;
        self
    }

    /// Sets flow configuration.
    #[must_use]
    pub fn with_flow_config(mut self, value: AuthFlowConfig) -> Self {
        self.flow_config = value;
        self
    }

    /// Updates flow configuration with a closure.
    #[must_use]
    pub fn configure_flows(
        mut self,
        update: impl FnOnce(AuthFlowConfig) -> AuthFlowConfig,
    ) -> Self {
        self.flow_config = update(self.flow_config);
        self
    }

    /// Sets route configuration.
    #[must_use]
    pub fn with_route_config(mut self, value: AuthRouteConfig) -> Self {
        self.route_config = value;
        self
    }

    /// Updates route configuration with a fallible closure.
    ///
    /// # Errors
    ///
    /// Returns [`HarborSetupError`] when route validation fails.
    pub fn configure_routes(
        mut self,
        update: impl FnOnce(AuthRouteConfig) -> Result<AuthRouteConfig, ConfigError>,
    ) -> Result<Self, HarborSetupError> {
        self.route_config = update(self.route_config)?;
        Ok(self)
    }

    /// Sets a Rust auth email renderer.
    #[must_use]
    pub fn with_email_renderer(mut self, renderer: impl AuthEmailRenderer) -> Self {
        self.email_renderer = Some(SharedEmailRenderer::new(renderer));
        self
    }

    /// Sets Harbor's default Rust email renderer.
    ///
    /// # Errors
    ///
    /// Returns [`HarborSetupError`] when a label is invalid.
    pub fn with_default_email_renderer(
        self,
        product_name: impl Into<String>,
        site_name: impl Into<String>,
    ) -> Result<Self, HarborSetupError> {
        let renderer = harbor_email::DefaultAuthEmailRenderer::new(product_name, site_name)?;
        Ok(self.with_email_renderer(renderer))
    }

    /// Opens SQLite, runs migrations, and returns initialized Harbor auth.
    ///
    /// # Errors
    ///
    /// Returns [`HarborSetupError`] when required setup inputs are missing,
    /// configuration is invalid, SQLite cannot open, or migrations fail.
    pub async fn connect(self) -> Result<SqliteHarbor<M>, HarborSetupError> {
        let database_url = self
            .database_url
            .ok_or(HarborSetupError::Missing("database_url"))?;
        let public_base_url = self
            .public_base_url
            .ok_or(HarborSetupError::Missing("public_base_url"))?;
        let hmac_key = self.hmac_key.ok_or(HarborSetupError::Missing("hmac_key"))?;
        let mailer = self.mailer.ok_or(HarborSetupError::Missing("mailer"))?;
        let email_renderer = self
            .email_renderer
            .ok_or(HarborSetupError::Missing("email_renderer"))?;
        let cookie_defaults = self
            .cookie_defaults
            .unwrap_or_else(|| cookie_defaults_for_public_url(&public_base_url));

        let store =
            SqliteAuthStore::connect_and_migrate(&database_url, self.sqlite_options).await?;
        let service = auth_service(
            store.clone(),
            hmac_key.clone(),
            self.password_policy,
            self.argon2_params,
        )?;
        let harbor = Harbor::builder()
            .with_store(store)
            .with_mailer(mailer)
            .with_public_base_url(public_base_url)?
            .with_cookie_defaults(cookie_defaults)?
            .with_hmac_secret_key(hmac_key)?
            .with_email_renderer(email_renderer)
            .finish()?;

        Ok(SqliteHarbor {
            harbor,
            service,
            flow_config: self.flow_config,
            route_config: self.route_config,
        })
    }
}

/// Error returned while initializing high-level Harbor Leptos auth.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HarborSetupError {
    /// Required setup value is missing.
    Missing(&'static str),
    /// Environment variable is missing.
    Env(&'static str),
    /// Harbor configuration failed validation.
    Config(ConfigError),
    /// Store initialization failed.
    Store(StoreError),
    /// Email setup failed.
    Mail(MailError),
}

impl fmt::Display for HarborSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(formatter, "missing Harbor setup value: {name}"),
            Self::Env(name) => write!(formatter, "missing Harbor environment variable: {name}"),
            Self::Config(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Mail(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for HarborSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Mail(error) => Some(error),
            Self::Missing(_) | Self::Env(_) => None,
        }
    }
}

impl From<ConfigError> for HarborSetupError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<StoreError> for HarborSetupError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<MailError> for HarborSetupError {
    fn from(value: MailError) -> Self {
        Self::Mail(value)
    }
}

#[derive(Clone)]
struct SharedEmailRenderer(Arc<dyn AuthEmailRenderer>);

impl SharedEmailRenderer {
    fn new(renderer: impl AuthEmailRenderer) -> Self {
        Self(Arc::new(renderer))
    }
}

impl fmt::Debug for SharedEmailRenderer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedEmailRenderer")
    }
}

impl AuthEmailRenderer for SharedEmailRenderer {
    fn render_challenge_email(
        &self,
        input: harbor_email::ChallengeEmailInput,
    ) -> Result<harbor_email::AuthEmail, MailError> {
        self.0.render_challenge_email(input)
    }
}

fn auth_service(
    store: SqliteAuthStore,
    hmac_key: Vec<u8>,
    password_policy: PasswordPolicy,
    argon2_params: Argon2Params,
) -> Result<SqliteHarborService, ConfigError> {
    let key = HmacSecretKey::try_new(hmac_key)
        .map_err(|_error| ConfigError::with_detail(ConfigErrorCode::WeakSecret, "hmac_key"))?;
    Ok(AuthService::new(
        store,
        SystemClock,
        SystemSecretGenerator,
        key,
        Argon2PasswordHasher::new(password_policy, argon2_params),
    ))
}

fn cookie_defaults_for_public_url(public_base_url: &str) -> CookieDefaults {
    if public_base_url.starts_with("https://") {
        CookieDefaults::production()
    } else {
        CookieDefaults::development()
    }
}

fn required_env(name: &'static str) -> Result<String, HarborSetupError> {
    std::env::var(name).map_err(|_error| HarborSetupError::Env(name))
}

fn optional_env(name: &'static str) -> Option<String> {
    std::env::var(name).ok()
}
