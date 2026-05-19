//! Integration tests for Harbor clock and randomness ports.

use harbor_core::{
    Clock, DomainError, RandomError, SecretGenerator, SystemClock, UnixTimestampMicros,
    new_auth_event_id, new_challenge_id, new_session_id, new_user_email_id, new_user_id,
    random_otp_code, random_session_token, random_url_token,
};

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
