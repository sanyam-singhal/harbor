use core::fmt;

use harbor_core::{MailError, MailErrorCode};

const MAX_SECRET_URL_BYTES: usize = 4096;

/// URL containing a challenge secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretUrl(String);

impl SecretUrl {
    /// Creates a redacted secret URL wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the URL is empty, too long, contains control
    /// characters, contains whitespace, or is not HTTPS except for local
    /// development hosts.
    pub fn try_new(value: impl Into<String>) -> Result<Self, MailError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "url_empty",
            ));
        }
        if value.len() > MAX_SECRET_URL_BYTES {
            return Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "url_long",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "url_control",
            ));
        }
        if value.chars().any(char::is_whitespace) {
            return Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "url_whitespace",
            ));
        }
        if !is_allowed_secret_url(&value) {
            return Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "url_scheme",
            ));
        }
        Ok(Self(value))
    }

    /// Exposes the URL for provider transmission.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretUrl([REDACTED])")
    }
}

fn is_allowed_secret_url(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let Some(host) = url_authority_host(rest) else {
        return false;
    };

    match scheme {
        "https" => true,
        "http" => is_local_development_host(host),
        _ => false,
    }
}

fn url_authority_host(rest: &str) -> Option<&str> {
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    if let Some(port) = port
        && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(host)
}

fn is_local_development_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

#[cfg(test)]
#[test]
fn secret_urls_require_https_except_local_development() {
    assert!(SecretUrl::try_new("https://app.example.com/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("http://localhost:3000/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("http://127.0.0.1:3000/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("").is_err());
    assert!(SecretUrl::try_new("https://").is_err());
    assert!(SecretUrl::try_new("https:///auth/email-link").is_err());
    assert!(SecretUrl::try_new(format!("https://{}", "a".repeat(4097))).is_err());
    assert!(SecretUrl::try_new("https://app.example.com/\n").is_err());
    assert!(SecretUrl::try_new("https://app.example.com/auth email-link").is_err());
    assert!(SecretUrl::try_new("http://example.com/auth/email-link").is_err());
    assert!(SecretUrl::try_new("http://localhost.evil.test/auth/email-link").is_err());
    assert!(SecretUrl::try_new("http://127.0.0.1.evil.test/auth/email-link").is_err());
    assert!(SecretUrl::try_new("http://localhost:bad/auth/email-link").is_err());
}

#[cfg(test)]
#[test]
fn secret_url_debug_redacts_secret() -> Result<(), Box<dyn std::error::Error>> {
    let secret_url = SecretUrl::try_new("https://app.example.com/auth/email-link?token=abc")?;

    assert_eq!(format!("{secret_url:?}"), "SecretUrl([REDACTED])");
    Ok(())
}
