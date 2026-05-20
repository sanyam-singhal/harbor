//! Route and redirect configuration for Harbor auth endpoints.

use harbor_core::{ConfigError, ConfigErrorCode};

const MAX_ROUTE_PATH_BYTES: usize = 256;

/// Route configuration for Harbor auth endpoints and redirects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRouteConfig {
    api_prefix: RoutePath,
    link_prefix: RoutePath,
    signin: RoutePath,
    account: RoutePath,
    reset_password: RoutePath,
    verified_redirect: RoutePath,
    error_redirect: RoutePath,
}

impl AuthRouteConfig {
    /// Creates route config with Harbor's defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a built-in default is invalid.
    pub fn new() -> Result<Self, ConfigError> {
        Ok(Self {
            api_prefix: RoutePath::try_new("/api/auth")?,
            link_prefix: RoutePath::try_new("/auth")?,
            signin: RoutePath::try_new("/signin")?,
            account: RoutePath::try_new("/account")?,
            reset_password: RoutePath::try_new("/reset-password")?,
            verified_redirect: RoutePath::try_new("/signin?notice=verified")?,
            error_redirect: RoutePath::try_new("/signin?notice=auth-error")?,
        })
    }

    /// Returns the API prefix.
    #[must_use]
    pub fn api_prefix(&self) -> &RoutePath {
        &self.api_prefix
    }

    /// Returns the link prefix.
    #[must_use]
    pub fn link_prefix(&self) -> &RoutePath {
        &self.link_prefix
    }

    /// Returns the sign-in page route.
    #[must_use]
    pub fn signin(&self) -> &RoutePath {
        &self.signin
    }

    /// Returns the post-auth account route.
    #[must_use]
    pub fn account(&self) -> &RoutePath {
        &self.account
    }

    /// Returns the reset-password page route.
    #[must_use]
    pub fn reset_password(&self) -> &RoutePath {
        &self.reset_password
    }

    /// Returns the email-confirmation success redirect.
    #[must_use]
    pub fn verified_redirect(&self) -> &RoutePath {
        &self.verified_redirect
    }

    /// Returns the auth error redirect.
    #[must_use]
    pub fn error_redirect(&self) -> &RoutePath {
        &self.error_redirect
    }

    /// Sets the API prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_api_prefix(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.api_prefix = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the link prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_link_prefix(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.link_prefix = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the sign-in page route.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_signin(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.signin = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the account page route.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_account(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.account = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the reset-password page route.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_reset_password(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.reset_password = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the email-confirmation success redirect.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_verified_redirect(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.verified_redirect = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Sets the auth error redirect.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is invalid.
    pub fn with_error_redirect(mut self, value: impl Into<String>) -> Result<Self, ConfigError> {
        self.error_redirect = RoutePath::try_new(value)?;
        Ok(self)
    }

    /// Returns the signup-confirmation link endpoint.
    #[must_use]
    pub fn confirm_email_link(&self) -> String {
        self.link_route("/confirm-email")
    }

    /// Returns the magic-link endpoint.
    #[must_use]
    pub fn magic_link(&self) -> String {
        self.link_route("/email-link")
    }

    /// Returns the reset-password link endpoint.
    #[must_use]
    pub fn reset_password_link(&self) -> String {
        self.link_route("/reset-password")
    }

    fn link_route(&self, suffix: &str) -> String {
        let mut route = String::with_capacity(self.link_prefix.as_str().len() + suffix.len());
        route.push_str(self.link_prefix.as_str());
        route.push_str(suffix);
        route
    }
}

impl Default for AuthRouteConfig {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_error| unreachable_default_routes())
    }
}

/// Same-origin application route path.
#[derive(Clone, PartialEq, Eq)]
pub struct RoutePath(String);

impl RoutePath {
    /// Creates a validated route path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the route is empty, too long, does not
    /// start with `/`, starts with `//`, or contains control characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        validate_route_path(&value)?;
        Ok(Self(value))
    }

    fn new_unchecked(value: &str) -> Self {
        Self(value.to_string())
    }

    /// Returns the route as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn unreachable_default_routes() -> AuthRouteConfig {
    AuthRouteConfig {
        api_prefix: RoutePath::new_unchecked("/api/auth"),
        link_prefix: RoutePath::new_unchecked("/auth"),
        signin: RoutePath::new_unchecked("/signin"),
        account: RoutePath::new_unchecked("/account"),
        reset_password: RoutePath::new_unchecked("/reset-password"),
        verified_redirect: RoutePath::new_unchecked("/signin?notice=verified"),
        error_redirect: RoutePath::new_unchecked("/signin?notice=auth-error"),
    }
}

impl core::fmt::Debug for RoutePath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_tuple("RoutePath").field(&self.0).finish()
    }
}

impl core::fmt::Display for RoutePath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_route_path(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "route_empty",
        ));
    }
    if value.len() > MAX_ROUTE_PATH_BYTES {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "route_long",
        ));
    }
    if !value.starts_with('/') || value.starts_with("//") {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "route_shape",
        ));
    }
    if value.contains('\\') || value.chars().any(char::is_control) {
        return Err(ConfigError::with_detail(
            ConfigErrorCode::Invalid,
            "route_chars",
        ));
    }
    Ok(())
}
