//! CSRF token issuance and double-submit validation.

use core::fmt;

use harbor_core::{
    AuthError, AuthErrorCode, SecretGenerator, SecretHashPurpose, SecretToken,
    constant_time_token_hash_eq, hash_secret, random_url_token,
};

use crate::{HarborConfig, lower_hex, parse_cookie_value};

const CSRF_TOKEN_SEPARATOR: char = '.';
const MAX_HEADER_NAME_BYTES: usize = 64;

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

/// Validated HTTP header name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// Creates a validated header name.
    ///
    /// # Errors
    ///
    /// Returns [`harbor_core::ConfigError`] when the header name is empty, too
    /// long, or contains invalid characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, harbor_core::ConfigError> {
        let value = value.into();
        let name = Self(value);
        name.validate()?;
        Ok(name)
    }

    pub(crate) fn new_unchecked(value: &str) -> Self {
        Self(value.to_owned())
    }

    pub(crate) fn validate(&self) -> Result<(), harbor_core::ConfigError> {
        if self.0.is_empty() {
            return Err(harbor_core::ConfigError::with_detail(
                harbor_core::ConfigErrorCode::Invalid,
                "header_name_empty",
            ));
        }
        if self.0.len() > MAX_HEADER_NAME_BYTES {
            return Err(harbor_core::ConfigError::with_detail(
                harbor_core::ConfigErrorCode::Invalid,
                "header_name_long",
            ));
        }
        if !self
            .0
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-'))
        {
            return Err(harbor_core::ConfigError::with_detail(
                harbor_core::ConfigErrorCode::Invalid,
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
