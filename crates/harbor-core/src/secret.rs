//! Keyed secret hashing utilities.

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::domain::{DomainError, SecretToken, TokenHash};

type HmacSha256 = Hmac<Sha256>;

const MIN_HMAC_SECRET_KEY_BYTES: usize = 32;

/// Application secret key used for keyed token hashing.
#[derive(Clone, PartialEq, Eq)]
pub struct HmacSecretKey(Vec<u8>);

impl HmacSecretKey {
    /// Creates a secret key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::OutOfRange`] when the key is shorter than 32
    /// bytes.
    pub fn try_new(value: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.len() < MIN_HMAC_SECRET_KEY_BYTES {
            return Err(DomainError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Exposes the key bytes to cryptographic code.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacSecretKey([REDACTED])")
    }
}

/// Domain separation context for keyed secret hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretHashPurpose {
    /// Browser session cookie token.
    SessionToken,
    /// URL token used in email links.
    UrlToken,
    /// Numeric OTP code delivered by email.
    OtpCode,
    /// CSRF token.
    CsrfToken,
    /// Request fingerprint, such as IP or user-agent hash input.
    RequestFingerprint,
}

impl SecretHashPurpose {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::SessionToken => b"harbor:v0.1:session-token",
            Self::UrlToken => b"harbor:v0.1:url-token",
            Self::OtpCode => b"harbor:v0.1:otp-code",
            Self::CsrfToken => b"harbor:v0.1:csrf-token",
            Self::RequestFingerprint => b"harbor:v0.1:request-fingerprint",
        }
    }
}

/// Hashes secret bytes with HMAC-SHA256 and purpose separation.
///
/// # Errors
///
/// Returns [`DomainError`] if the generated hash fails Harbor validation.
pub fn hash_secret(
    key: &HmacSecretKey,
    purpose: SecretHashPurpose,
    secret: &[u8],
) -> Result<TokenHash, DomainError> {
    let mut mac = HmacSha256::new_from_slice(key.expose_secret())
        .map_err(|_error| DomainError::InvalidFormat)?;
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(secret);
    TokenHash::try_new(mac.finalize().into_bytes().to_vec())
}

/// Hashes a [`SecretToken`] with HMAC-SHA256 and purpose separation.
///
/// # Errors
///
/// Returns [`DomainError`] if the generated hash fails Harbor validation.
pub fn hash_secret_token(
    key: &HmacSecretKey,
    purpose: SecretHashPurpose,
    token: &SecretToken,
) -> Result<TokenHash, DomainError> {
    hash_secret(key, purpose, token.expose_secret().as_bytes())
}

/// Compares two token hashes without data-dependent byte comparison.
#[must_use]
pub fn constant_time_token_hash_eq(left: &TokenHash, right: &TokenHash) -> bool {
    left.as_bytes().len() == right.as_bytes().len()
        && left.as_bytes().ct_eq(right.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::{
        HmacSecretKey, SecretHashPurpose, constant_time_token_hash_eq, hash_secret,
        hash_secret_token,
    };
    use crate::{DomainError, SecretToken};

    fn test_key() -> Result<HmacSecretKey, DomainError> {
        HmacSecretKey::try_new(vec![7; 32])
    }

    #[test]
    fn hmac_secret_key_debug_is_redacted() -> Result<(), DomainError> {
        let key = test_key()?;

        assert_eq!(format!("{key:?}"), "HmacSecretKey([REDACTED])");
        assert_eq!(key.expose_secret().len(), 32);
        assert!(HmacSecretKey::try_new(vec![1; 31]).is_err());
        Ok(())
    }

    #[test]
    fn hash_secret_is_stable_for_same_context() -> Result<(), DomainError> {
        let key = test_key()?;

        let first = hash_secret(&key, SecretHashPurpose::SessionToken, b"token")?;
        let second = hash_secret(&key, SecretHashPurpose::SessionToken, b"token")?;

        assert!(constant_time_token_hash_eq(&first, &second));
        assert_eq!(first.as_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn hash_secret_is_domain_separated() -> Result<(), DomainError> {
        let key = test_key()?;

        let session = hash_secret(&key, SecretHashPurpose::SessionToken, b"same-token")?;
        let url = hash_secret(&key, SecretHashPurpose::UrlToken, b"same-token")?;

        assert!(!constant_time_token_hash_eq(&session, &url));
        Ok(())
    }

    #[test]
    fn hash_secret_token_accepts_redacted_token_wrapper() -> Result<(), DomainError> {
        let key = test_key()?;
        let token = SecretToken::try_new("12345678")?;

        let hash = hash_secret_token(&key, SecretHashPurpose::OtpCode, &token)?;

        assert_eq!(format!("{hash:?}"), "TokenHash([REDACTED])");
        assert_eq!(hash.as_bytes().len(), 32);
        Ok(())
    }
}
