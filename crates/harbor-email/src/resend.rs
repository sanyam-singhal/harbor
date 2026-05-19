use core::fmt;

use harbor_core::{EmailAddress, MailError, MailErrorCode};
use resend_rs::{Resend, types::CreateEmailBaseOptions};

use crate::{AuthEmail, AuthMailer, MailDelivery};

const MAX_RESEND_API_KEY_BYTES: usize = 256;
const RESEND_API_BASE_URL: &str = "https://api.resend.com";

/// Resend-backed auth mailer.
#[derive(Clone)]
pub struct ResendMailer {
    client: Resend,
    from: String,
}

impl ResendMailer {
    /// Creates a Resend mailer.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the API key or sender are invalid.
    pub fn new(api_key: impl Into<String>, from: impl Into<String>) -> Result<Self, MailError> {
        let api_key = api_key.into();
        validate_resend_api_key(&api_key)?;
        let from = from.into();
        validate_resend_from(&from)?;
        let base_url = RESEND_API_BASE_URL
            .parse()
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "base_url"))?;
        Ok(Self {
            client: Resend::with_config(
                resend_rs::Config::builder(api_key)
                    .base_url(base_url)
                    .build(),
            ),
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

impl fmt::Debug for ResendMailer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResendMailer")
            .field("client", &"[REDACTED]")
            .field("from", &self.from)
            .finish()
    }
}

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

fn validate_resend_api_key(api_key: &str) -> Result<(), MailError> {
    if api_key.is_empty() {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_empty",
        ));
    }
    if api_key.len() > MAX_RESEND_API_KEY_BYTES {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_long",
        ));
    }
    if api_key.chars().any(char::is_whitespace) {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "api_key_whitespace",
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
    if resend_from_address(from).is_none() {
        return Err(MailError::with_detail(
            MailErrorCode::InvalidConfig,
            "from_address",
        ));
    }
    Ok(())
}

fn resend_from_address(from: &str) -> Option<()> {
    let address = match from.rsplit_once('<') {
        Some((display_name, bracketed_address)) => {
            if display_name.contains('>') {
                return None;
            }
            bracketed_address.strip_suffix('>')?
        }
        None => from,
    }
    .trim();

    EmailAddress::parse(address).ok()?;
    Some(())
}

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

#[cfg(test)]
fn spawn_resend_server(
    status: &'static str,
    extra_headers: &'static str,
    body: &'static str,
) -> Result<
    (
        String,
        std::thread::JoinHandle<Result<String, std::io::Error>>,
    ),
    std::io::Error,
> {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let handle = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept()?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let mut buffer = [0_u8; 8192];
        let read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
        let response = format!(
            "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        Ok(request)
    });
    Ok((format!("http://{addr}"), handle))
}

#[cfg(test)]
fn join_resend_server(
    handle: std::thread::JoinHandle<Result<String, std::io::Error>>,
) -> Result<String, Box<dyn std::error::Error>> {
    match handle.join() {
        Ok(Ok(request)) => Ok(request),
        Ok(Err(error)) => Err(error.into()),
        Err(_payload) => Err(std::io::Error::other("resend test server panicked").into()),
    }
}

#[cfg(test)]
fn render_with_default(input: crate::ChallengeEmailInput) -> Result<AuthEmail, MailError> {
    let renderer = crate::DefaultAuthEmailRenderer::new("TestAuth", "test app")?;
    crate::render_challenge_email_with_renderer(input, &renderer)
}

#[cfg(test)]
#[test]
fn resend_mailer_validates_configuration_without_sending() {
    assert!(ResendMailer::new("", "Harbor <auth@example.com>").is_err());
    assert!(ResendMailer::new("re_".to_owned() + &"a".repeat(257), "auth@example.com").is_err());
    assert!(ResendMailer::new("re_\n", "Harbor <auth@example.com>").is_err());
    assert!(ResendMailer::new("re_ test", "Harbor <auth@example.com>").is_err());
    assert!(ResendMailer::new("not-a-resend-key", "Harbor <auth@example.com>").is_err());
    assert!(ResendMailer::new("re_test", "").is_err());
    assert!(ResendMailer::new("re_test", "a".repeat(321)).is_err());
    assert!(ResendMailer::new("re_test", "Harbor\n<auth@example.com>").is_err());
    assert!(ResendMailer::new("re_test", "missing-at").is_err());
    assert!(ResendMailer::new("re_test", "Harbor <missing-at>").is_err());
    assert!(ResendMailer::new("re_test", "Harbor <auth@example.com").is_err());

    let mailer = ResendMailer::new("re_test", "Harbor <auth@example.com>");
    assert!(mailer.is_ok());
}

#[cfg(test)]
#[test]
fn resend_mailer_debug_redacts_client() -> Result<(), Box<dyn std::error::Error>> {
    let mailer = ResendMailer::new("re_test", "Harbor <auth@example.com>")?;

    assert_eq!(mailer.from(), "Harbor <auth@example.com>");
    let debug = format!("{mailer:?}");
    assert!(debug.contains("ResendMailer"));
    assert!(!debug.contains("re_test"));
    Ok(())
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn resend_mailer_sends_to_configured_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let (base_url, server) = spawn_resend_server("HTTP/1.1 200 OK", "", "{\"id\":\"email_test\"}")?;
    let mailer = ResendMailer::with_base_url("re_test", "Harbor <auth@example.com>", &base_url)?;
    let email = render_with_default(crate::ChallengeEmailInput {
        purpose: harbor_core::ChallengePurpose::EmailSignIn,
        delivery: harbor_core::ChallengeDelivery::MagicLink,
        to: crate::EmailRecipient::parse("User@Example.com")?,
        challenge_id: harbor_core::ChallengeId::try_new("challenge00000003")?,
        action_url: Some(crate::SecretUrl::try_new(
            "https://app.example.com/auth/email-link?challenge=challenge00000003&token=abc",
        )?),
        otp_code: None,
    })?;

    let delivery = mailer.send_auth_email(email).await?;
    let request = join_resend_server(server)?;

    assert_eq!(delivery.provider_message_id, Some("email_test".to_owned()));
    assert!(request.starts_with("POST /emails HTTP/1.1"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer re_test")
    );
    assert!(request.contains("\"html\""));
    Ok(())
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn resend_mailer_maps_rate_limits() -> Result<(), Box<dyn std::error::Error>> {
    let (base_url, server) = spawn_resend_server(
        "HTTP/1.1 429 Too Many Requests",
        "ratelimit-limit: 2\r\nratelimit-remaining: 0\r\nratelimit-reset: 60\r\n",
        "{\"name\":\"rate_limit_exceeded\",\"message\":\"slow down\",\"statusCode\":429}",
    )?;
    let mailer = ResendMailer::with_base_url("re_test", "Harbor <auth@example.com>", &base_url)?;
    let email = render_with_default(crate::ChallengeEmailInput {
        purpose: harbor_core::ChallengePurpose::EmailSignIn,
        delivery: harbor_core::ChallengeDelivery::MagicLink,
        to: crate::EmailRecipient::parse("user@example.com")?,
        challenge_id: harbor_core::ChallengeId::try_new("challenge00000004")?,
        action_url: Some(crate::SecretUrl::try_new(
            "https://app.example.com/auth/email-link?challenge=challenge00000004&token=abc",
        )?),
        otp_code: None,
    })?;

    let error = match mailer.send_auth_email(email).await {
        Ok(_) => return Err("rate-limited response should fail".into()),
        Err(error) => error,
    };
    let _request = join_resend_server(server)?;

    assert_eq!(error.code(), harbor_core::MailErrorCode::RateLimited);
    Ok(())
}
