use core::fmt;

use harbor_core::{ChallengeDelivery, ChallengePurpose, MailError, MailErrorCode, SecretToken};

use crate::message::{AuthEmail, ChallengeEmailInput, validate_rendered_email_label};
use crate::url::SecretUrl;

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
        validate_rendered_email_label(&product_name, "product_name")?;
        validate_rendered_email_label(&site_name, "site_name")?;
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

impl AuthEmailRenderer for DefaultAuthEmailRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        validate_template_secrets(
            input.delivery,
            input.action_url.as_ref(),
            input.otp_code.as_ref(),
        )?;
        AuthEmail::try_new(
            input.purpose,
            input.to,
            input.challenge_id,
            self.subject(input.purpose),
            self.text_body(
                input.purpose,
                input.action_url.as_ref(),
                input.otp_code.as_ref(),
            ),
            Some(self.html_body(
                input.purpose,
                input.action_url.as_ref(),
                input.otp_code.as_ref(),
            )),
        )
    }
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
    validate_template_secrets(
        input.delivery,
        input.action_url.as_ref(),
        input.otp_code.as_ref(),
    )?;
    renderer.render_challenge_email(input)
}

fn validate_template_secrets(
    delivery: ChallengeDelivery,
    action_url: Option<&SecretUrl>,
    otp_code: Option<&SecretToken>,
) -> Result<(), MailError> {
    match delivery {
        ChallengeDelivery::MagicLink if action_url.is_some() => Ok(()),
        ChallengeDelivery::OtpCode if otp_code.is_some() => Ok(()),
        ChallengeDelivery::MagicLink | ChallengeDelivery::OtpCode => Err(MailError::with_detail(
            MailErrorCode::Internal,
            "missing_challenge_secret",
        )),
        _ => Err(MailError::with_detail(
            MailErrorCode::Internal,
            "unknown_delivery",
        )),
    }
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
#[derive(Debug)]
struct AppRenderer;

#[cfg(test)]
impl AuthEmailRenderer for AppRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        AuthEmail::try_new(
            input.purpose,
            input.to,
            input.challenge_id,
            "App auth subject".to_owned(),
            "App auth text".to_owned(),
            Some("<p>App auth HTML</p>".to_owned()),
        )
    }
}

#[cfg(test)]
fn render_with_default(input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
    let renderer = DefaultAuthEmailRenderer::new("TestAuth", "test app")?;
    render_challenge_email_with_renderer(input, &renderer)
}

#[cfg(test)]
#[test]
fn default_renderer_validates_and_exposes_app_labels() -> Result<(), Box<dyn std::error::Error>> {
    let renderer = DefaultAuthEmailRenderer::new("Product", "example.com")?;

    assert_eq!(renderer.product_name(), "Product");
    assert_eq!(renderer.site_name(), "example.com");
    assert!(DefaultAuthEmailRenderer::new("", "example.com").is_err());
    assert!(DefaultAuthEmailRenderer::new("Product", "").is_err());
    assert!(DefaultAuthEmailRenderer::new("x".repeat(16 * 1024 + 1), "example.com").is_err());
    assert!(DefaultAuthEmailRenderer::new("Product\n", "example.com").is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn template_requires_secret_matching_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let result = render_with_default(ChallengeEmailInput {
        purpose: ChallengePurpose::EmailSignIn,
        delivery: ChallengeDelivery::OtpCode,
        to: crate::EmailRecipient::parse("user@example.com")?,
        challenge_id: harbor_core::ChallengeId::try_new("challenge00000001")?,
        action_url: None,
        otp_code: None,
    });

    assert!(result.is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn otp_template_renders_code_and_escapes_html() -> Result<(), Box<dyn std::error::Error>> {
    let email = render_with_default(ChallengeEmailInput {
        purpose: ChallengePurpose::EmailSignIn,
        delivery: ChallengeDelivery::OtpCode,
        to: crate::EmailRecipient::parse("user@example.com")?,
        challenge_id: harbor_core::ChallengeId::try_new("challenge00000001")?,
        action_url: None,
        otp_code: Some(harbor_core::SecretToken::try_new("12345678")?),
    })?;
    let html = match email.html_body() {
        Some(html) => html,
        None => return Err("html body should render".into()),
    };

    assert!(email.text_body().contains("12345678"));
    assert!(email.subject().contains("TestAuth"));
    assert!(html.contains("<strong>12345678</strong>"));
    assert!(!format!("{email:?}").contains("12345678"));
    Ok(())
}

#[cfg(test)]
#[test]
fn magic_link_template_renders_link_and_html_escapes() -> Result<(), Box<dyn std::error::Error>> {
    let secret_url =
        SecretUrl::try_new("https://app.example.com/auth/email-link?x=<tag>&quote=\"'")?;
    let email = render_with_default(ChallengeEmailInput {
        purpose: ChallengePurpose::PasswordReset,
        delivery: ChallengeDelivery::MagicLink,
        to: crate::EmailRecipient::parse("user@example.com")?,
        challenge_id: harbor_core::ChallengeId::try_new("challenge00000002")?,
        action_url: Some(secret_url.clone()),
        otp_code: None,
    })?;
    let html = match email.html_body() {
        Some(html) => html,
        None => return Err("html body should render".into()),
    };

    assert_eq!(email.subject(), "Reset your TestAuth password");
    assert!(email.text_body().contains(secret_url.expose_secret()));
    assert!(html.contains("&lt;tag&gt;"));
    assert!(html.contains("&quot;&#39;"));
    Ok(())
}

#[cfg(test)]
#[test]
fn rust_renderer_can_own_application_email_templates() -> Result<(), Box<dyn std::error::Error>> {
    let email = render_challenge_email_with_renderer(
        ChallengeEmailInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            to: crate::EmailRecipient::parse("user@example.com")?,
            challenge_id: harbor_core::ChallengeId::try_new("challenge00000003")?,
            action_url: Some(SecretUrl::try_new(
                "https://app.example.com/auth/email-link?challenge=challenge00000003&token=abc",
            )?),
            otp_code: None,
        },
        &AppRenderer,
    )?;

    assert_eq!(email.subject(), "App auth subject");
    assert_eq!(email.text_body(), "App auth text");
    assert_eq!(email.html_body(), Some("<p>App auth HTML</p>"));
    Ok(())
}
