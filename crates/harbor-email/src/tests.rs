use harbor_core::{ChallengeDelivery, ChallengeId, ChallengePurpose, SecretToken};

use super::{
    AuthEmail, AuthEmailRenderer, AuthMailer, ChallengeEmailInput, EmailRecipient, MailError,
    RecordingMailer, SecretUrl, render_challenge_email, render_challenge_email_with_renderer,
};

#[derive(Debug)]
struct AppRenderer;

impl AuthEmailRenderer for AppRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        Ok(AuthEmail::new(
            input.purpose,
            input.to,
            input.challenge_id,
            "App auth subject".to_owned(),
            "App auth text".to_owned(),
            Some("<p>App auth HTML</p>".to_owned()),
        ))
    }
}

#[cfg(feature = "email-resend")]
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

#[cfg(feature = "email-resend")]
fn join_resend_server(
    handle: std::thread::JoinHandle<Result<String, std::io::Error>>,
) -> Result<String, Box<dyn std::error::Error>> {
    match handle.join() {
        Ok(Ok(request)) => Ok(request),
        Ok(Err(error)) => Err(error.into()),
        Err(_payload) => Err(std::io::Error::other("resend test server panicked").into()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn recording_mailer_captures_rendered_email() -> Result<(), Box<dyn std::error::Error>> {
    let mailer = RecordingMailer::new();
    let email = render_challenge_email(ChallengeEmailInput {
        purpose: ChallengePurpose::SignupConfirmation,
        delivery: ChallengeDelivery::MagicLink,
        to: EmailRecipient::parse("User@Example.com")?,
        challenge_id: ChallengeId::try_new("challenge00000001")?,
        action_url: Some(SecretUrl::try_new(
            "https://app.example.com/auth/confirm-email?challenge=challenge00000001&token=abc",
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
    assert_eq!(sent.subject(), "Confirm your Harbor sign-up");
    assert!(
        sent.text_body()
            .contains("https://app.example.com/auth/confirm-email")
    );
    assert!(
        sent.text_body()
            .contains("You requested a Harbor account for your application")
    );
    assert!(sent.text_body().contains("If you did not request this"));
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
    assert!(email.subject().contains("Harbor"));
    assert!(html.contains("<strong>12345678</strong>"));
    assert!(!format!("{email:?}").contains("12345678"));
    Ok(())
}

#[test]
fn combined_template_renders_link_code_and_html_escapes() -> Result<(), Box<dyn std::error::Error>>
{
    let secret_url =
        SecretUrl::try_new("https://app.example.com/auth/email-link?x=<tag>&quote=\"'")?;
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
fn rust_renderer_can_own_application_email_templates() -> Result<(), Box<dyn std::error::Error>> {
    let email = render_challenge_email_with_renderer(
        ChallengeEmailInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            to: EmailRecipient::parse("user@example.com")?,
            challenge_id: ChallengeId::try_new("challenge00000003")?,
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

#[test]
fn secret_urls_require_https_except_local_development() {
    assert!(SecretUrl::try_new("https://app.example.com/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("http://localhost:3000/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("http://127.0.0.1:3000/auth/email-link").is_ok());
    assert!(SecretUrl::try_new("").is_err());
    assert!(SecretUrl::try_new(format!("https://{}", "a".repeat(4097))).is_err());
    assert!(SecretUrl::try_new("https://app.example.com/\n").is_err());
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

#[cfg(feature = "email-resend")]
#[tokio::test(flavor = "current_thread")]
async fn resend_mailer_sends_to_configured_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let (base_url, server) = spawn_resend_server("HTTP/1.1 200 OK", "", "{\"id\":\"email_test\"}")?;
    let mailer =
        super::ResendMailer::with_base_url("re_test", "Harbor <auth@example.com>", &base_url)?;
    let email = render_challenge_email(ChallengeEmailInput {
        purpose: ChallengePurpose::EmailSignIn,
        delivery: ChallengeDelivery::Both,
        to: EmailRecipient::parse("User@Example.com")?,
        challenge_id: ChallengeId::try_new("challenge00000003")?,
        action_url: Some(SecretUrl::try_new(
            "https://app.example.com/auth/email-link?challenge=challenge00000003&token=abc",
        )?),
        otp_code: Some(SecretToken::try_new("12345678")?),
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

#[cfg(feature = "email-resend")]
#[tokio::test(flavor = "current_thread")]
async fn resend_mailer_maps_rate_limits() -> Result<(), Box<dyn std::error::Error>> {
    let (base_url, server) = spawn_resend_server(
        "HTTP/1.1 429 Too Many Requests",
        "ratelimit-limit: 2\r\nratelimit-remaining: 0\r\nratelimit-reset: 60\r\n",
        "{\"name\":\"rate_limit_exceeded\",\"message\":\"slow down\",\"statusCode\":429}",
    )?;
    let mailer =
        super::ResendMailer::with_base_url("re_test", "Harbor <auth@example.com>", &base_url)?;
    let email = render_challenge_email(ChallengeEmailInput {
        purpose: ChallengePurpose::EmailSignIn,
        delivery: ChallengeDelivery::MagicLink,
        to: EmailRecipient::parse("user@example.com")?,
        challenge_id: ChallengeId::try_new("challenge00000004")?,
        action_url: Some(SecretUrl::try_new(
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
