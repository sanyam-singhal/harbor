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
const MAX_RENDERED_EMAIL_FIELD_BYTES: usize = 16 * 1024;
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

/// Auth email rendering boundary.
///
/// Applications can implement this trait in ordinary Rust files and return
/// fully rendered subject, plain text, and HTML bodies. Harbor then sends the
/// returned [`AuthEmail`] through the configured mailer.
pub trait AuthEmailRenderer: fmt::Debug + Send + Sync + 'static {
    /// Renders a challenge email.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the input is unsupported or the rendered
    /// email would violate Harbor's email bounds.
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError>;
}

/// Default Rust renderer for Harbor auth emails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultAuthEmailRenderer {
    product_name: String,
    site_name: String,
}

impl DefaultAuthEmailRenderer {
    /// Creates Harbor's default Rust auth email renderer.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the product or site name is empty, too
    /// long, or contains control characters.
    pub fn new(
        product_name: impl Into<String>,
        site_name: impl Into<String>,
    ) -> Result<Self, MailError> {
        let product_name = product_name.into();
        let site_name = site_name.into();
        validate_rendered_email_field(&product_name, "product_name")?;
        validate_rendered_email_field(&site_name, "site_name")?;
        Ok(Self {
            product_name,
            site_name,
        })
    }

    /// Returns the configured product name.
    #[must_use]
    pub fn product_name(&self) -> &str {
        &self.product_name
    }

    /// Returns the configured site name.
    #[must_use]
    pub fn site_name(&self) -> &str {
        &self.site_name
    }
}

impl AuthEmailRenderer for DefaultAuthEmailRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        validate_template_secrets(
            input.delivery,
            input.action_url.as_ref(),
            input.otp_code.as_ref(),
        )?;
        let subject = self.subject(input.purpose);
        let text_body = self.text_body(
            input.purpose,
            input.action_url.as_ref(),
            input.otp_code.as_ref(),
        );
        let html_body = Some(self.html_body(
            input.purpose,
            input.action_url.as_ref(),
            input.otp_code.as_ref(),
        ));
        bounded_auth_email(input, subject, text_body, html_body)
    }
}

impl DefaultAuthEmailRenderer {
    fn subject(&self, purpose: ChallengePurpose) -> String {
        match purpose {
            ChallengePurpose::SignupConfirmation => {
                format!("Confirm your {} sign-up", self.product_name)
            }
            ChallengePurpose::EmailSignIn => format!("Sign in to {}", self.product_name),
            ChallengePurpose::PasswordReset => format!("Reset your {} password", self.product_name),
            _ => format!("{} auth email", self.product_name),
        }
    }

    fn text_body(
        &self,
        purpose: ChallengePurpose,
        action_url: Option<&SecretUrl>,
        otp_code: Option<&SecretToken>,
    ) -> String {
        let mut body = self.intro(purpose);
        if let Some(url) = action_url {
            body.push_str("\n\nOpen this secure link:\n");
            body.push_str(url.expose_secret());
        }
        if let Some(code) = otp_code {
            body.push_str("\n\nUse this code:\n");
            body.push_str(code.expose_secret());
        }
        body.push_str("\n\nIf you did not request this, you can ignore this email.");
        body.push_str(" Do not share this link or code.");
        body
    }

    fn html_body(
        &self,
        purpose: ChallengePurpose,
        action_url: Option<&SecretUrl>,
        otp_code: Option<&SecretToken>,
    ) -> String {
        let mut body = String::from("<p>");
        body.push_str(escape_html(&self.intro(purpose)).as_str());
        body.push_str("</p>");
        if let Some(url) = action_url {
            body.push_str("<p><a href=\"");
            body.push_str(escape_html(url.expose_secret()).as_str());
            body.push_str("\">Open secure link</a></p>");
        }
        if let Some(code) = otp_code {
            body.push_str("<p>Code: <strong>");
            body.push_str(escape_html(code.expose_secret()).as_str());
            body.push_str("</strong></p>");
        }
        body.push_str("<p>If you did not request this, you can ignore this email. ");
        body.push_str("Do not share this link or code.</p>");
        body
    }

    fn intro(&self, purpose: ChallengePurpose) -> String {
        match purpose {
            ChallengePurpose::SignupConfirmation => format!(
                "You requested a {} account for {}. Confirm this email address to finish signing up.",
                self.product_name, self.site_name
            ),
            ChallengePurpose::EmailSignIn => format!(
                "You requested to sign in to {} for {}.",
                self.product_name, self.site_name
            ),
            ChallengePurpose::PasswordReset => format!(
                "You requested to reset your {} password for {}.",
                self.product_name, self.site_name
            ),
            _ => format!("Use this {} auth challenge to continue.", self.product_name),
        }
    }
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
    let renderer = DefaultAuthEmailRenderer::new("Harbor", "your application")?;
    renderer.render_challenge_email(input)
}

/// Renders an auth challenge email using a caller-provided Rust renderer.
///
/// # Errors
///
/// Returns [`MailError`] when the requested delivery style is missing its
/// required secret material or the renderer rejects the input.
pub fn render_challenge_email_with_renderer(
    input: ChallengeEmailInput,
    renderer: &(impl AuthEmailRenderer + ?Sized),
) -> Result<AuthEmail, MailError> {
    renderer.render_challenge_email(input)
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
    /// Reads `RESEND_API_KEY` and `HARBOR_EMAIL_FROM`.
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
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "from"))?;
        Self::new(api_key, from)
    }

    /// Returns the configured sender.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    #[cfg(test)]
    fn with_base_url(
        api_key: impl Into<String>,
        from: impl Into<String>,
        base_url: &str,
    ) -> Result<Self, MailError> {
        let api_key = api_key.into();
        let from = from.into();
        validate_resend_api_key(&api_key)?;
        validate_resend_from(&from)?;
        let base_url = base_url
            .parse()
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "base_url"))?;
        let client = Resend::with_config(
            resend_rs::Config::builder(api_key)
                .base_url(base_url)
                .build(),
        );
        Ok(Self { client, from })
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

fn bounded_auth_email(
    input: ChallengeEmailInput,
    subject: String,
    text_body: String,
    html_body: Option<String>,
) -> Result<AuthEmail, MailError> {
    validate_rendered_email_field(&subject, "subject")?;
    validate_rendered_email_field(&text_body, "text_body")?;
    if let Some(html_body) = html_body.as_ref() {
        validate_rendered_email_field(html_body, "html_body")?;
    }
    Ok(AuthEmail::new(
        input.purpose,
        input.to,
        input.challenge_id,
        subject,
        text_body,
        html_body,
    ))
}

fn validate_rendered_email_field(value: &str, detail: &'static str) -> Result<(), MailError> {
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

fn is_allowed_secret_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

/// Escapes text for simple HTML email rendering.
#[must_use]
pub fn escape_html(value: &str) -> String {
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
mod tests;
