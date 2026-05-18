//! Email delivery integrations for Harbor.
//!
//! This crate keeps provider-specific delivery outside `harbor-core` while
//! exposing a small, testable boundary for auth emails.

use core::{fmt, future::Future};
use std::sync::{Arc, Mutex};

use harbor_core::{
    CanonicalEmail, ChallengeDelivery, ChallengeId, ChallengePurpose, EmailAddress, MailError,
    MailErrorCode, SecretToken,
};

#[cfg(feature = "email-resend")]
use resend_rs::{Resend, types::CreateEmailBaseOptions};

/// Version of the `harbor-email` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_SECRET_URL_BYTES: usize = 4096;
#[cfg(feature = "email-resend")]
const DEFAULT_RESEND_FROM: &str = "Harbor <auth@issuecertificate.com>";

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

/// Recipient accepted by Harbor email delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailRecipient {
    original: String,
    canonical: CanonicalEmail,
}

impl EmailRecipient {
    /// Parses and canonicalizes an email recipient.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the address is not accepted by Harbor's
    /// conservative email parser.
    pub fn parse(value: impl Into<String>) -> Result<Self, MailError> {
        let email = EmailAddress::parse(value)
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "recipient"))?;
        Ok(Self {
            original: email.original().to_owned(),
            canonical: email.canonical().clone(),
        })
    }

    /// Returns the original accepted email spelling.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Returns the canonical lookup email.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalEmail {
        &self.canonical
    }
}

impl fmt::Debug for EmailRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailRecipient")
            .field("canonical", &self.canonical)
            .finish_non_exhaustive()
    }
}

/// URL containing a challenge secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretUrl(String);

impl SecretUrl {
    /// Creates a redacted secret URL wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the URL is empty, too long, contains control
    /// characters, or is not HTTPS except for local development hosts.
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
    /// Creates a rendered auth email.
    #[must_use]
    pub fn new(
        kind: ChallengePurpose,
        to: EmailRecipient,
        challenge_id: ChallengeId,
        subject: String,
        text_body: String,
        html_body: Option<String>,
    ) -> Self {
        Self {
            kind,
            to,
            challenge_id,
            subject,
            text_body,
            html_body,
        }
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
    pub otp_code: Option<SecretToken>,
}

/// Successful mail delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailDelivery {
    /// Provider message id, when the provider returns one.
    pub provider_message_id: Option<String>,
}

/// Renders an auth challenge email.
///
/// # Errors
///
/// Returns [`MailError`] when the requested delivery style is missing its
/// required secret material.
pub fn render_challenge_email(input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
    validate_template_secrets(
        input.delivery,
        input.action_url.as_ref(),
        input.otp_code.as_ref(),
    )?;
    let subject = subject_for_purpose(input.purpose).to_owned();
    let text_body = render_text_body(
        input.purpose,
        input.action_url.as_ref(),
        input.otp_code.as_ref(),
    );
    let html_body = Some(render_html_body(
        input.purpose,
        input.action_url.as_ref(),
        input.otp_code.as_ref(),
    ));

    Ok(AuthEmail::new(
        input.purpose,
        input.to,
        input.challenge_id,
        subject,
        text_body,
        html_body,
    ))
}

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

/// Resend-backed auth mailer.
#[cfg(feature = "email-resend")]
#[derive(Clone)]
pub struct ResendMailer {
    client: Resend,
    from: String,
}

#[cfg(feature = "email-resend")]
impl ResendMailer {
    /// Creates a Resend mailer.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the API key or sender are invalid.
    ///
    /// # Panics
    ///
    /// The upstream `resend-rs` constructor can panic if `RESEND_BASE_URL` is
    /// present but not a valid URL.
    pub fn new(api_key: impl Into<String>, from: impl Into<String>) -> Result<Self, MailError> {
        let api_key = api_key.into();
        validate_resend_api_key(&api_key)?;
        let from = from.into();
        validate_resend_from(&from)?;
        Ok(Self {
            client: Resend::new(&api_key),
            from,
        })
    }

    /// Creates a Resend mailer from environment variables.
    ///
    /// Reads `RESEND_API_KEY` and optional `HARBOR_EMAIL_FROM`. When
    /// `HARBOR_EMAIL_FROM` is absent, Harbor uses
    /// `Harbor <auth@issuecertificate.com>`.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when required configuration is missing or invalid.
    ///
    /// # Panics
    ///
    /// The upstream `resend-rs` constructor can panic if `RESEND_BASE_URL` is
    /// present but not a valid URL.
    pub fn from_env() -> Result<Self, MailError> {
        let api_key = std::env::var("RESEND_API_KEY")
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "api_key"))?;
        let from = std::env::var("HARBOR_EMAIL_FROM")
            .unwrap_or_else(|_error| DEFAULT_RESEND_FROM.to_owned());
        Self::new(api_key, from)
    }

    /// Returns the configured sender.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }
}

#[cfg(feature = "email-resend")]
impl fmt::Debug for ResendMailer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResendMailer")
            .field("client", &"[REDACTED]")
            .field("from", &self.from)
            .finish()
    }
}

#[cfg(feature = "email-resend")]
impl AuthMailer for ResendMailer {
    async fn send_auth_email(&self, email: AuthEmail) -> Result<MailDelivery, MailError> {
        let mut options = CreateEmailBaseOptions::new(
            self.from.clone(),
            [email.to().original().to_owned()],
            email.subject().to_owned(),
        )
        .with_text(email.text_body());
        if let Some(html) = email.html_body() {
            options = options.with_html(html);
        }

        let response = self
            .client
            .emails
            .send(options)
            .await
            .map_err(map_resend_error)?;
        Ok(MailDelivery {
            provider_message_id: Some(response.id.to_string()),
        })
    }
}

#[cfg(feature = "email-resend")]
fn validate_resend_api_key(api_key: &str) -> Result<(), MailError> {
    if api_key.is_empty() {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_empty",
        ));
    }
    if api_key.chars().any(char::is_control) {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_control",
        ));
    }
    if !api_key.starts_with("re_") {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_prefix",
        ));
    }
    Ok(())
}

#[cfg(feature = "email-resend")]
fn validate_resend_from(from: &str) -> Result<(), MailError> {
    if from.is_empty() {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "from_empty",
        ));
    }
    if from.len() > 320 {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "from_long",
        ));
    }
    if from.chars().any(char::is_control) {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "from_control",
        ));
    }
    if !from.contains('@') {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "from_missing_at",
        ));
    }
    Ok(())
}

#[cfg(feature = "email-resend")]
fn map_resend_error(error: resend_rs::Error) -> MailError {
    match error {
        resend_rs::Error::RateLimit { .. } => MailError::new(MailErrorCode::RateLimited),
        resend_rs::Error::Resend(_) => MailError::new(MailErrorCode::Rejected),
        resend_rs::Error::Http(_) => MailError::new(MailErrorCode::Unavailable),
        resend_rs::Error::Parse { .. } | resend_rs::Error::Other(_) => {
            MailError::new(MailErrorCode::Internal)
        }
    }
}

fn validate_template_secrets(
    delivery: ChallengeDelivery,
    action_url: Option<&SecretUrl>,
    otp_code: Option<&SecretToken>,
) -> Result<(), MailError> {
    match delivery {
        ChallengeDelivery::MagicLink if action_url.is_some() => Ok(()),
        ChallengeDelivery::OtpCode if otp_code.is_some() => Ok(()),
        ChallengeDelivery::Both if action_url.is_some() && otp_code.is_some() => Ok(()),
        ChallengeDelivery::MagicLink | ChallengeDelivery::OtpCode | ChallengeDelivery::Both => Err(
            MailError::with_detail(MailErrorCode::Internal, "missing_challenge_secret"),
        ),
        _ => Err(MailError::with_detail(
            MailErrorCode::Internal,
            "unknown_delivery",
        )),
    }
}

fn render_text_body(
    purpose: ChallengePurpose,
    action_url: Option<&SecretUrl>,
    otp_code: Option<&SecretToken>,
) -> String {
    let mut body = String::from(intro_for_purpose(purpose));
    if let Some(url) = action_url {
        body.push_str("\n\nOpen this link:\n");
        body.push_str(url.expose_secret());
    }
    if let Some(code) = otp_code {
        body.push_str("\n\nUse this code:\n");
        body.push_str(code.expose_secret());
    }
    body.push_str("\n\nThis message was sent by Harbor. Do not share this link or code.");
    body
}

fn render_html_body(
    purpose: ChallengePurpose,
    action_url: Option<&SecretUrl>,
    otp_code: Option<&SecretToken>,
) -> String {
    let mut body = String::from("<p>");
    body.push_str(escape_html(intro_for_purpose(purpose)).as_str());
    body.push_str("</p>");
    if let Some(url) = action_url {
        body.push_str("<p><a href=\"");
        body.push_str(escape_html(url.expose_secret()).as_str());
        body.push_str("\">Open Harbor</a></p>");
    }
    if let Some(code) = otp_code {
        body.push_str("<p>Code: <strong>");
        body.push_str(escape_html(code.expose_secret()).as_str());
        body.push_str("</strong></p>");
    }
    body.push_str("<p>Do not share this link or code.</p>");
    body
}

fn subject_for_purpose(purpose: ChallengePurpose) -> &'static str {
    match purpose {
        ChallengePurpose::SignupConfirmation => "Confirm your Harbor email",
        ChallengePurpose::EmailSignIn => "Sign in to Harbor",
        ChallengePurpose::PasswordReset => "Reset your Harbor password",
        _ => "Harbor auth email",
    }
}

fn intro_for_purpose(purpose: ChallengePurpose) -> &'static str {
    match purpose {
        ChallengePurpose::SignupConfirmation => "Confirm your email address to finish signing up.",
        ChallengePurpose::EmailSignIn => "Use this email challenge to sign in to Harbor.",
        ChallengePurpose::PasswordReset => {
            "Use this password reset challenge to choose a new password."
        }
        _ => "Use this Harbor auth challenge to continue.",
    }
}

fn is_allowed_secret_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use harbor_core::{ChallengeDelivery, ChallengeId, ChallengePurpose, SecretToken};

    use super::{
        AuthMailer, ChallengeEmailInput, EmailRecipient, RecordingMailer, SecretUrl,
        render_challenge_email,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn recording_mailer_captures_rendered_email() -> Result<(), Box<dyn std::error::Error>> {
        let mailer = RecordingMailer::new();
        let email = render_challenge_email(ChallengeEmailInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            to: EmailRecipient::parse("User@Example.com")?,
            challenge_id: ChallengeId::try_new("challenge00000001")?,
            action_url: Some(SecretUrl::try_new(
                "https://issuecertificate.com/auth/confirm-email?challenge=challenge00000001&token=abc",
            )?),
            otp_code: None,
        })?;

        mailer.send_auth_email(email).await?;
        let recorded = mailer.recorded()?;
        let sent = match recorded.as_slice() {
            [email] => email,
            _ => return Err("one email should be recorded".into()),
        };

        assert_eq!(sent.to().canonical().as_str(), "user@example.com");
        assert_eq!(sent.to().original(), "User@Example.com");
        assert_eq!(sent.kind(), ChallengePurpose::SignupConfirmation);
        assert_eq!(sent.challenge_id().as_str(), "challenge00000001");
        assert_eq!(sent.subject(), "Confirm your Harbor email");
        assert!(
            sent.text_body()
                .contains("https://issuecertificate.com/auth/confirm-email")
        );
        assert!(!format!("{sent:?}").contains("abc"));
        mailer.clear()?;
        assert!(mailer.recorded()?.is_empty());
        Ok(())
    }

    #[test]
    fn template_requires_secret_matching_delivery() -> Result<(), Box<dyn std::error::Error>> {
        let result = render_challenge_email(ChallengeEmailInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::OtpCode,
            to: EmailRecipient::parse("user@example.com")?,
            challenge_id: ChallengeId::try_new("challenge00000001")?,
            action_url: None,
            otp_code: None,
        });

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn otp_template_renders_code_and_escapes_html() -> Result<(), Box<dyn std::error::Error>> {
        let email = render_challenge_email(ChallengeEmailInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::OtpCode,
            to: EmailRecipient::parse("user@example.com")?,
            challenge_id: ChallengeId::try_new("challenge00000001")?,
            action_url: None,
            otp_code: Some(SecretToken::try_new("12345678")?),
        })?;
        let html = match email.html_body() {
            Some(html) => html,
            None => return Err("html body should render".into()),
        };

        assert!(email.text_body().contains("12345678"));
        assert!(html.contains("<strong>12345678</strong>"));
        assert!(!format!("{email:?}").contains("12345678"));
        Ok(())
    }

    #[test]
    fn combined_template_renders_link_code_and_html_escapes()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_url =
            SecretUrl::try_new("https://issuecertificate.com/auth/email-link?x=<tag>&quote=\"'")?;
        let email = render_challenge_email(ChallengeEmailInput {
            purpose: ChallengePurpose::PasswordReset,
            delivery: ChallengeDelivery::Both,
            to: EmailRecipient::parse("user@example.com")?,
            challenge_id: ChallengeId::try_new("challenge00000002")?,
            action_url: Some(secret_url.clone()),
            otp_code: Some(SecretToken::try_new("87654321")?),
        })?;
        let html = match email.html_body() {
            Some(html) => html,
            None => return Err("html body should render".into()),
        };

        assert_eq!(email.subject(), "Reset your Harbor password");
        assert!(email.text_body().contains(secret_url.expose_secret()));
        assert!(email.text_body().contains("87654321"));
        assert!(html.contains("&lt;tag&gt;"));
        assert!(html.contains("&quot;&#39;"));
        assert_eq!(format!("{secret_url:?}"), "SecretUrl([REDACTED])");
        Ok(())
    }

    #[test]
    fn secret_urls_require_https_except_local_development() {
        assert!(SecretUrl::try_new("https://issuecertificate.com/auth/email-link").is_ok());
        assert!(SecretUrl::try_new("http://localhost:3000/auth/email-link").is_ok());
        assert!(SecretUrl::try_new("http://127.0.0.1:3000/auth/email-link").is_ok());
        assert!(SecretUrl::try_new("").is_err());
        assert!(SecretUrl::try_new(format!("https://{}", "a".repeat(4097))).is_err());
        assert!(SecretUrl::try_new("https://issuecertificate.com/\n").is_err());
        assert!(SecretUrl::try_new("http://example.com/auth/email-link").is_err());
    }

    #[test]
    fn invalid_recipient_maps_to_mail_error() {
        assert!(EmailRecipient::parse("not-an-email").is_err());
    }

    #[cfg(feature = "email-resend")]
    #[test]
    fn resend_mailer_validates_configuration_without_sending() {
        assert!(super::ResendMailer::new("", "Harbor <auth@example.com>").is_err());
        assert!(super::ResendMailer::new("re_\n", "Harbor <auth@example.com>").is_err());
        assert!(super::ResendMailer::new("not-a-resend-key", "Harbor <auth@example.com>").is_err());
        assert!(super::ResendMailer::new("re_test", "").is_err());
        assert!(super::ResendMailer::new("re_test", "a".repeat(321)).is_err());
        assert!(super::ResendMailer::new("re_test", "Harbor\n<auth@example.com>").is_err());
        assert!(super::ResendMailer::new("re_test", "missing-at").is_err());

        let mailer = super::ResendMailer::new("re_test", "Harbor <auth@example.com>");
        assert!(mailer.is_ok());
    }

    #[cfg(feature = "email-resend")]
    #[test]
    fn resend_mailer_debug_redacts_client() -> Result<(), Box<dyn std::error::Error>> {
        let mailer = super::ResendMailer::new("re_test", "Harbor <auth@example.com>")?;

        assert_eq!(mailer.from(), "Harbor <auth@example.com>");
        let debug = format!("{mailer:?}");
        assert!(debug.contains("ResendMailer"));
        assert!(!debug.contains("re_test"));
        Ok(())
    }
}
