use core::{fmt, future::Future};

use harbor_core::{ChallengeDelivery, ChallengeId, ChallengePurpose, MailError, MailErrorCode};

use crate::{EmailRecipient, SecretUrl};

pub(crate) const MAX_RENDERED_EMAIL_FIELD_BYTES: usize = 16 * 1024;

/// Email delivery boundary used by Harbor web integrations.
pub trait AuthMailer: Clone + Send + Sync + 'static {
    /// Sends an auth email.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when validation or provider delivery fails.
    fn send_auth_email(
        &self,
        email: AuthEmail,
    ) -> impl Future<Output = Result<MailDelivery, MailError>> + Send;
}

/// Rendered auth email.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthEmail {
    kind: ChallengePurpose,
    to: EmailRecipient,
    challenge_id: ChallengeId,
    subject: String,
    text_body: String,
    html_body: Option<String>,
}

impl AuthEmail {
    /// Creates a rendered auth email after enforcing Harbor's email bounds.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when any rendered field is empty, too long, or
    /// contains disallowed control characters.
    pub fn try_new(
        kind: ChallengePurpose,
        to: EmailRecipient,
        challenge_id: ChallengeId,
        subject: String,
        text_body: String,
        html_body: Option<String>,
    ) -> Result<Self, MailError> {
        validate_rendered_email_label(&subject, "subject")?;
        validate_rendered_email_field(&text_body, "text_body")?;
        if let Some(html_body) = html_body.as_ref() {
            validate_rendered_email_field(html_body, "html_body")?;
        }
        Ok(Self {
            kind,
            to,
            challenge_id,
            subject,
            text_body,
            html_body,
        })
    }

    /// Returns the auth email kind.
    #[must_use]
    pub const fn kind(&self) -> ChallengePurpose {
        self.kind
    }

    /// Returns the recipient.
    #[must_use]
    pub const fn to(&self) -> &EmailRecipient {
        &self.to
    }

    /// Returns the related challenge id.
    #[must_use]
    pub const fn challenge_id(&self) -> &ChallengeId {
        &self.challenge_id
    }

    /// Returns the rendered subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the rendered plaintext body.
    #[must_use]
    pub fn text_body(&self) -> &str {
        &self.text_body
    }

    /// Returns the rendered HTML body, if any.
    #[must_use]
    pub fn html_body(&self) -> Option<&str> {
        self.html_body.as_deref()
    }
}

impl fmt::Debug for AuthEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthEmail")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("challenge_id", &self.challenge_id)
            .field("subject", &self.subject)
            .field("text_body", &"[REDACTED]")
            .field(
                "html_body",
                &self.html_body.as_ref().map(|_body| "[REDACTED]"),
            )
            .finish()
    }
}

/// Input for rendering an auth challenge email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeEmailInput {
    /// Challenge purpose.
    pub purpose: ChallengePurpose,
    /// Delivery style requested for the challenge.
    pub delivery: ChallengeDelivery,
    /// Recipient.
    pub to: EmailRecipient,
    /// Challenge id.
    pub challenge_id: ChallengeId,
    /// Secret action URL for magic-link delivery.
    pub action_url: Option<SecretUrl>,
    /// Secret OTP code for code delivery.
    pub otp_code: Option<harbor_core::SecretToken>,
}

/// Successful mail delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailDelivery {
    /// Provider message id, when the provider returns one.
    pub provider_message_id: Option<String>,
}

pub(crate) fn validate_rendered_email_field(
    value: &str,
    detail: &'static str,
) -> Result<(), MailError> {
    if value.is_empty() {
        return Err(MailError::with_detail(MailErrorCode::InvalidConfig, detail));
    }
    if value.len() > MAX_RENDERED_EMAIL_FIELD_BYTES {
        return Err(MailError::with_detail(MailErrorCode::InvalidConfig, detail));
    }
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return Err(MailError::with_detail(MailErrorCode::InvalidConfig, detail));
    }
    Ok(())
}

pub(crate) fn validate_rendered_email_label(
    value: &str,
    detail: &'static str,
) -> Result<(), MailError> {
    validate_rendered_email_field(value, detail)?;
    if value.chars().any(char::is_control) {
        return Err(MailError::with_detail(MailErrorCode::InvalidConfig, detail));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn auth_email_bounds_rendered_fields() -> Result<(), Box<dyn std::error::Error>> {
    let to = EmailRecipient::parse("user@example.com")?;
    let challenge_id = ChallengeId::try_new("challenge00000001")?;

    assert!(
        AuthEmail::try_new(
            ChallengePurpose::EmailSignIn,
            to.clone(),
            challenge_id.clone(),
            String::new(),
            "body".to_owned(),
            None,
        )
        .is_err()
    );
    assert!(
        AuthEmail::try_new(
            ChallengePurpose::EmailSignIn,
            to.clone(),
            challenge_id.clone(),
            "subject".to_owned(),
            String::new(),
            None,
        )
        .is_err()
    );
    assert!(
        AuthEmail::try_new(
            ChallengePurpose::EmailSignIn,
            to.clone(),
            challenge_id.clone(),
            "subject\n".to_owned(),
            "body".to_owned(),
            None,
        )
        .is_err()
    );

    let email = AuthEmail::try_new(
        ChallengePurpose::EmailSignIn,
        to,
        challenge_id,
        "subject".to_owned(),
        harbor_core::SecretToken::try_new("12345678")?
            .expose_secret()
            .to_owned(),
        None,
    )?;
    assert!(!format!("{email:?}").contains("12345678"));
    Ok(())
}
