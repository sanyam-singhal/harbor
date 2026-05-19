//! Cookie policy and `Set-Cookie` helpers.

use core::fmt;

use harbor_core::{ConfigError, ConfigErrorCode, SecretToken};

const MAX_COOKIE_NAME_BYTES: usize = 64;

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
    pub(crate) session_cookie_name: CookieName,
    pub(crate) csrf_cookie_name: CookieName,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) session_http_only: bool,
    pub(crate) csrf_http_only: bool,
    pub(crate) same_site: SameSite,
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

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

pub(crate) fn build_cookie_header(
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

fn same_site_value(same_site: SameSite) -> &'static str {
    match same_site {
        SameSite::Lax => "Lax",
        SameSite::Strict => "Strict",
        SameSite::None => "None",
    }
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

    pub(crate) fn new_unchecked(value: &str) -> Self {
        Self(value.to_owned())
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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
