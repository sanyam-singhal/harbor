//! Ports for time and cryptographically secure randomness.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    AuthEventId, ChallengeId, DomainError, SecretToken, SessionId, UnixTimestampMicros,
    UserEmailId, UserId,
};

const OPAQUE_ID_BYTES: usize = 16;
const SECRET_TOKEN_BYTES: usize = 32;
const DEFAULT_OTP_DIGITS: usize = 8;

/// Time source used by Harbor services.
pub trait Clock: Clone + Send + Sync + 'static {
    /// Returns the current UTC time as Unix microseconds.
    fn now(&self) -> UnixTimestampMicros;
}

/// System UTC clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTimestampMicros {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let micros = duration.as_micros();
                if micros > i64::MAX as u128 {
                    UnixTimestampMicros::try_new(i64::MAX).unwrap_or(UnixTimestampMicros::EPOCH)
                } else {
                    UnixTimestampMicros::try_new(micros as i64)
                        .unwrap_or(UnixTimestampMicros::EPOCH)
                }
            }
            Err(_) => UnixTimestampMicros::EPOCH,
        }
    }
}

/// Error returned by random generation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RandomError {
    /// The operating system random source failed.
    SystemRandom,
    /// A generated value failed Harbor domain validation.
    Domain(DomainError),
    /// The requested OTP digit count is outside Harbor's bounds.
    InvalidOtpDigits,
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemRandom => formatter.write_str("system random source failed"),
            Self::Domain(error) => write!(formatter, "generated value failed validation: {error}"),
            Self::InvalidOtpDigits => formatter.write_str("invalid OTP digit count"),
        }
    }
}

impl std::error::Error for RandomError {}

impl From<DomainError> for RandomError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}

/// Secret byte generator.
pub trait SecretGenerator: Clone + Send + Sync + 'static {
    /// Fills `dest` with cryptographically suitable random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] if the generator cannot fill the destination.
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError>;
}

/// Operating-system-backed secret generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSecretGenerator;

impl SecretGenerator for SystemSecretGenerator {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(dest).map_err(|_error| RandomError::SystemRandom)
    }
}

/// Generates a new user identifier.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated identifier
/// fails validation.
pub fn new_user_id(generator: &impl SecretGenerator) -> Result<UserId, RandomError> {
    UserId::try_new(random_hex(generator, OPAQUE_ID_BYTES)?).map_err(RandomError::from)
}

/// Generates a new session row identifier.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated identifier
/// fails validation.
pub fn new_session_id(generator: &impl SecretGenerator) -> Result<SessionId, RandomError> {
    SessionId::try_new(random_hex(generator, OPAQUE_ID_BYTES)?).map_err(RandomError::from)
}

/// Generates a new challenge row identifier.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated identifier
/// fails validation.
pub fn new_challenge_id(generator: &impl SecretGenerator) -> Result<ChallengeId, RandomError> {
    ChallengeId::try_new(random_hex(generator, OPAQUE_ID_BYTES)?).map_err(RandomError::from)
}

/// Generates a new user email row identifier.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated identifier
/// fails validation.
pub fn new_user_email_id(generator: &impl SecretGenerator) -> Result<UserEmailId, RandomError> {
    UserEmailId::try_new(random_hex(generator, OPAQUE_ID_BYTES)?).map_err(RandomError::from)
}

/// Generates a new auth event row identifier.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated identifier
/// fails validation.
pub fn new_auth_event_id(generator: &impl SecretGenerator) -> Result<AuthEventId, RandomError> {
    AuthEventId::try_new(random_hex(generator, OPAQUE_ID_BYTES)?).map_err(RandomError::from)
}

/// Generates a session token with 256 bits of entropy.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated token fails
/// validation.
pub fn random_session_token(generator: &impl SecretGenerator) -> Result<SecretToken, RandomError> {
    SecretToken::try_new(random_hex(generator, SECRET_TOKEN_BYTES)?).map_err(RandomError::from)
}

/// Generates a URL token with 256 bits of entropy.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or the generated token fails
/// validation.
pub fn random_url_token(generator: &impl SecretGenerator) -> Result<SecretToken, RandomError> {
    SecretToken::try_new(random_hex(generator, SECRET_TOKEN_BYTES)?).map_err(RandomError::from)
}

/// Generates Harbor's default eight-digit OTP code.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails.
pub fn random_otp_code(generator: &impl SecretGenerator) -> Result<SecretToken, RandomError> {
    random_otp_code_with_digits(generator, DEFAULT_OTP_DIGITS)
}

/// Generates a numeric OTP code with the requested number of digits.
///
/// # Errors
///
/// Returns [`RandomError`] if randomness fails or `digits` is outside the range
/// `6..=12`.
pub fn random_otp_code_with_digits(
    generator: &impl SecretGenerator,
    digits: usize,
) -> Result<SecretToken, RandomError> {
    if !(6..=12).contains(&digits) {
        return Err(RandomError::InvalidOtpDigits);
    }
    let upper_bound = pow10(digits).ok_or(RandomError::InvalidOtpDigits)?;
    let value = random_u64_below(generator, upper_bound)?;
    SecretToken::try_new(format!("{value:0digits$}")).map_err(RandomError::from)
}

fn random_hex(generator: &impl SecretGenerator, byte_count: usize) -> Result<String, RandomError> {
    let mut bytes = vec![0_u8; byte_count];
    generator.fill_bytes(&mut bytes)?;
    Ok(lower_hex(&bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn random_u64_below(
    generator: &impl SecretGenerator,
    upper_bound: u64,
) -> Result<u64, RandomError> {
    let zone = u64::MAX - (u64::MAX % upper_bound);
    loop {
        let mut bytes = [0_u8; 8];
        generator.fill_bytes(&mut bytes)?;
        let candidate = u64::from_le_bytes(bytes);
        if candidate < zone {
            return Ok(candidate % upper_bound);
        }
    }
}

fn pow10(digits: usize) -> Option<u64> {
    let mut value = 1_u64;
    for _ in 0..digits {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::{
        Clock, RandomError, SecretGenerator, SystemClock, new_auth_event_id, new_challenge_id,
        new_session_id, new_user_email_id, new_user_id, random_otp_code,
        random_otp_code_with_digits, random_session_token, random_url_token,
    };
    use crate::{DomainError, UnixTimestampMicros};

    #[derive(Clone)]
    struct FixedGenerator {
        byte: u8,
    }

    impl SecretGenerator for FixedGenerator {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            dest.fill(self.byte);
            Ok(())
        }
    }

    #[test]
    fn system_clock_returns_non_negative_time() {
        assert!(SystemClock.now() >= UnixTimestampMicros::EPOCH);
    }

    #[test]
    fn generated_ids_are_valid_hex_values() -> Result<(), RandomError> {
        let generator = FixedGenerator { byte: 0xab };

        assert_eq!(
            new_user_id(&generator)?.as_str(),
            "abababababababababababababababab"
        );
        assert_eq!(
            new_session_id(&generator)?.as_str(),
            "abababababababababababababababab"
        );
        assert_eq!(
            new_challenge_id(&generator)?.as_str(),
            "abababababababababababababababab"
        );
        assert_eq!(
            new_user_email_id(&generator).map(|id| id.as_str().to_owned()),
            Ok("abababababababababababababababab".to_owned())
        );
        assert_eq!(
            new_auth_event_id(&generator).map(|id| id.as_str().to_owned()),
            Ok("abababababababababababababababab".to_owned())
        );
        Ok(())
    }

    #[test]
    fn generated_tokens_are_256_bit_hex_values() -> Result<(), RandomError> {
        let generator = FixedGenerator { byte: 0x1f };

        assert_eq!(random_session_token(&generator)?.expose_secret().len(), 64);
        assert_eq!(random_url_token(&generator)?.expose_secret().len(), 64);
        Ok(())
    }

    #[test]
    fn generated_otp_uses_requested_width() -> Result<(), RandomError> {
        let generator = FixedGenerator { byte: 0 };

        assert_eq!(random_otp_code(&generator)?.expose_secret(), "00000000");
        assert_eq!(
            random_otp_code_with_digits(&generator, 6)?.expose_secret(),
            "000000"
        );
        assert!(random_otp_code_with_digits(&generator, 5).is_err());
        assert!(random_otp_code_with_digits(&generator, 13).is_err());
        Ok(())
    }

    #[test]
    fn random_error_display_and_conversion_are_stable() {
        assert_eq!(
            RandomError::SystemRandom.to_string(),
            "system random source failed"
        );
        assert_eq!(
            RandomError::from(DomainError::Empty).to_string(),
            "generated value failed validation: value is empty"
        );
        assert_eq!(
            RandomError::InvalidOtpDigits.to_string(),
            "invalid OTP digit count"
        );
    }
}
