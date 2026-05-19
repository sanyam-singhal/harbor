use std::sync::{Arc, Mutex};

use harbor_core::{MailError, MailErrorCode};

use crate::{AuthEmail, AuthMailer, MailDelivery};

/// In-memory mailer for tests and local demos.
#[derive(Debug, Clone, Default)]
pub struct RecordingMailer {
    deliveries: Arc<Mutex<Vec<AuthEmail>>>,
}

impl RecordingMailer {
    /// Creates an empty recording mailer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns recorded messages.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] if another thread poisoned the recorder mutex.
    pub fn recorded(&self) -> Result<Vec<AuthEmail>, MailError> {
        let deliveries = self
            .deliveries
            .lock()
            .map_err(|_error| MailError::with_detail(MailErrorCode::Internal, "record_lock"))?;
        Ok(deliveries.clone())
    }

    /// Clears recorded messages.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] if another thread poisoned the recorder mutex.
    pub fn clear(&self) -> Result<(), MailError> {
        let mut deliveries = self
            .deliveries
            .lock()
            .map_err(|_error| MailError::with_detail(MailErrorCode::Internal, "record_lock"))?;
        deliveries.clear();
        Ok(())
    }
}

impl AuthMailer for RecordingMailer {
    async fn send_auth_email(&self, email: AuthEmail) -> Result<MailDelivery, MailError> {
        let mut deliveries = self
            .deliveries
            .lock()
            .map_err(|_error| MailError::with_detail(MailErrorCode::Internal, "record_lock"))?;
        deliveries.push(email);
        Ok(MailDelivery {
            provider_message_id: None,
        })
    }
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn recording_mailer_captures_rendered_email() -> Result<(), Box<dyn std::error::Error>> {
    let mailer = RecordingMailer::new();
    let renderer = crate::DefaultAuthEmailRenderer::new("TestAuth", "test app")?;
    let email = crate::render_challenge_email_with_renderer(
        crate::ChallengeEmailInput {
            purpose: harbor_core::ChallengePurpose::SignupConfirmation,
            delivery: harbor_core::ChallengeDelivery::MagicLink,
            to: crate::EmailRecipient::parse("User@Example.com")?,
            challenge_id: harbor_core::ChallengeId::try_new("challenge00000001")?,
            action_url: Some(crate::SecretUrl::try_new(
                "https://app.example.com/auth/confirm-email?challenge=challenge00000001&token=abc",
            )?),
            otp_code: None,
        },
        &renderer,
    )?;

    mailer.send_auth_email(email).await?;
    let recorded = mailer.recorded()?;
    let sent = match recorded.as_slice() {
        [email] => email,
        _ => return Err("one email should be recorded".into()),
    };

    assert_eq!(sent.to().canonical().as_str(), "user@example.com");
    assert_eq!(sent.to().original(), "User@Example.com");
    assert_eq!(
        sent.kind(),
        harbor_core::ChallengePurpose::SignupConfirmation
    );
    assert_eq!(sent.challenge_id().as_str(), "challenge00000001");
    assert_eq!(sent.subject(), "Confirm your TestAuth sign-up");
    assert!(
        sent.text_body()
            .contains("https://app.example.com/auth/confirm-email")
    );
    assert!(
        sent.text_body()
            .contains("You requested a TestAuth account for test app")
    );
    assert!(sent.text_body().contains("If you did not request this"));
    assert!(!format!("{sent:?}").contains("abc"));
    mailer.clear()?;
    assert!(mailer.recorded()?.is_empty());
    Ok(())
}
