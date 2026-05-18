//! Harbor shell, builder, and Leptos context helpers.

use harbor_core::{ConfigError, ConfigErrorCode, HmacSecretKey, PasswordPolicy};

use crate::{
    AuthRateLimits, ChallengeLifetimes, CookieDefaults, HarborConfig, HarborConfigBuilder,
    PublicBaseUrl,
};

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
