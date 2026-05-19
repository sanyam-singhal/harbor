//! Headless smoke harness for Harbor.

use std::env;

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, ChallengeDelivery, ChallengeId, Clock,
    HmacSecretKey, MailError, PasswordPolicy, RedirectPath, SecretToken, SystemClock,
    SystemSecretGenerator,
};
#[cfg(feature = "email-resend")]
use harbor_email::ResendMailer;
use harbor_email::{
    AuthEmail, AuthMailer, DefaultAuthEmailRenderer, MailDelivery, RecordingMailer,
};
use harbor_leptos::{CookieDefaults, CsrfRequest, Harbor, build_csrf_cookie, issue_csrf_token};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

mod browser;

use browser::{
    assert_current_session, first_cookie_pair, latest_link_query, latest_otp_code,
    run_browser_smoke_server,
};

const DEFAULT_DATABASE_URL: &str = "sqlite://harbor-headless-demo.sqlite?mode=rwc";
const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:3000";
const DEFAULT_DEMO_ADDR: &str = "127.0.0.1:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = DemoSettings::from_env()?;
    let store = SqliteAuthStore::connect_and_migrate(
        &settings.database_url,
        sqlite_options_for_url(&settings.database_url),
    )
    .await?;
    let recording_mailer = RecordingMailer::new();
    let mailer = DemoMailer::from_mode(settings.email_mode, recording_mailer.clone())?;
    let harbor = Harbor::builder()
        .with_store(store.clone())
        .with_mailer(mailer.clone())
        .with_public_base_url(settings.public_base_url.clone())?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(settings.hmac_key.clone())?
        .with_email_renderer(DefaultAuthEmailRenderer::new(
            settings.product_name.clone(),
            settings.email_site_name(),
        )?)
        .finish()?;

    println!(
        "Harbor headless demo initialized: base_url={}, session_cookie={}",
        harbor.config().public_base_url(),
        harbor
            .config()
            .cookie_defaults()
            .session_cookie_name()
            .as_str()
    );
    println!("Headless demo mail mode: {}", mailer.mode_name());
    if settings.run_smoke {
        run_recording_smoke(
            store.clone(),
            mailer.clone(),
            recording_mailer.clone(),
            harbor.config(),
            settings.hmac_key.clone(),
            settings.smoke_email.clone(),
        )
        .await?;
        println!("Headless demo auth smoke: ok");
    }
    if settings.run_browser_smoke {
        let service = auth_service(store, settings.hmac_key)?;
        run_browser_smoke_server(
            &settings.demo_addr,
            service,
            recording_mailer,
            harbor.config().clone(),
        )
        .await?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoSettings {
    database_url: String,
    public_base_url: String,
    product_name: String,
    email_site_name: Option<String>,
    hmac_key: Vec<u8>,
    email_mode: DemoEmailMode,
    smoke_email: Option<String>,
    run_smoke: bool,
    run_browser_smoke: bool,
    demo_addr: String,
}

impl DemoSettings {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            database_url: env::var("HARBOR_DATABASE_URL")
                .unwrap_or_else(|_error| DEFAULT_DATABASE_URL.to_owned()),
            public_base_url: env::var("HARBOR_PUBLIC_BASE_URL")
                .unwrap_or_else(|_error| DEFAULT_PUBLIC_BASE_URL.to_owned()),
            product_name: env::var("HARBOR_PRODUCT_NAME")
                .unwrap_or_else(|_error| "Harbor".to_owned()),
            email_site_name: env::var("HARBOR_EMAIL_SITE_NAME").ok(),
            hmac_key: env::var("HARBOR_HMAC_KEY")
                .map(|value| value.into_bytes())
                .unwrap_or_else(|_error| vec![42; 32]),
            email_mode: DemoEmailMode::from_env()?,
            smoke_email: env::var("HARBOR_HEADLESS_DEMO_SMOKE_EMAIL").ok(),
            run_smoke: env_bool("HARBOR_HEADLESS_DEMO_SMOKE"),
            run_browser_smoke: env_bool("HARBOR_HEADLESS_DEMO_BROWSER_SMOKE"),
            demo_addr: env::var("HARBOR_HEADLESS_DEMO_ADDR")
                .unwrap_or_else(|_error| DEFAULT_DEMO_ADDR.to_owned()),
        })
    }

    fn email_site_name(&self) -> String {
        self.email_site_name
            .clone()
            .unwrap_or_else(|| display_host(&self.public_base_url).to_owned())
    }
}

fn env_bool(name: &str) -> bool {
    env::var(name)
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DemoEmailMode {
    Recording,
    Resend,
}

impl DemoEmailMode {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        match env::var("HARBOR_EMAIL_MODE")
            .unwrap_or_else(|_error| "recording".to_owned())
            .as_str()
        {
            "recording" | "log" => Ok(Self::Recording),
            "resend" => Ok(Self::Resend),
            _ => Err("HARBOR_EMAIL_MODE must be recording, log, or resend".into()),
        }
    }
}

#[derive(Clone)]
enum DemoMailer {
    Recording(RecordingMailer),
    #[cfg(feature = "email-resend")]
    Resend {
        recording: RecordingMailer,
        resend: ResendMailer,
    },
}

impl DemoMailer {
    fn from_mode(
        mode: DemoEmailMode,
        recording: RecordingMailer,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match mode {
            DemoEmailMode::Recording => Ok(Self::Recording(recording)),
            DemoEmailMode::Resend => Self::resend(recording),
        }
    }

    #[cfg(feature = "email-resend")]
    fn resend(recording: RecordingMailer) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::Resend {
            recording,
            resend: ResendMailer::from_env()?,
        })
    }

    #[cfg(not(feature = "email-resend"))]
    fn resend(_recording: RecordingMailer) -> Result<Self, Box<dyn std::error::Error>> {
        Err(
            "HARBOR_EMAIL_MODE=resend requires `cargo run -p harbor-headless-demo --features email-resend`".into(),
        )
    }

    fn mode_name(&self) -> &'static str {
        match self {
            Self::Recording(_recording) => "recording",
            #[cfg(feature = "email-resend")]
            Self::Resend {
                recording: _recording,
                resend: _resend,
            } => "resend",
        }
    }
}

impl std::fmt::Debug for DemoMailer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DemoMailer")
            .field("mode", &self.mode_name())
            .finish_non_exhaustive()
    }
}

impl AuthMailer for DemoMailer {
    async fn send_auth_email(&self, email: AuthEmail) -> Result<MailDelivery, MailError> {
        match self {
            Self::Recording(recording) => recording.send_auth_email(email).await,
            #[cfg(feature = "email-resend")]
            Self::Resend { recording, resend } => {
                recording.send_auth_email(email.clone()).await?;
                resend.send_auth_email(email).await
            }
        }
    }
}

fn sqlite_options_for_url(database_url: &str) -> SqliteStoreOptions {
    if database_url.contains(":memory:") {
        SqliteStoreOptions::in_memory()
    } else {
        SqliteStoreOptions::default()
    }
}

fn display_host(public_base_url: &str) -> &str {
    let without_scheme = public_base_url
        .strip_prefix("https://")
        .or_else(|| public_base_url.strip_prefix("http://"))
        .unwrap_or(public_base_url);
    without_scheme.split('/').next().unwrap_or(without_scheme)
}

async fn run_recording_smoke(
    store: SqliteAuthStore,
    mailer: DemoMailer,
    recording_mailer: RecordingMailer,
    config: &harbor_leptos::HarborConfig,
    hmac_key: Vec<u8>,
    smoke_email: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = auth_service(store, hmac_key)?;
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let csrf_cookie_pair = first_cookie_pair(&csrf_cookie)?;
    let csrf_request = CsrfRequest {
        cookie_header: Some(csrf_cookie_pair.to_owned()),
        csrf_header: Some(csrf.expose_secret().to_owned()),
        rate_limit_key: None,
    };
    let email = smoke_email_for_run(smoke_email, SystemClock.now().as_i64())?;
    let password = "correct horse battery staple".to_owned();

    harbor_leptos::signup_with_password(
        &service,
        &mailer,
        config,
        csrf_request.clone(),
        harbor_core::PasswordSignUpInput {
            email: email.clone(),
            password: password.clone(),
        },
    )
    .await?;
    let confirmation = latest_link_query(&recording_mailer)?;
    harbor_leptos::handle_confirm_email_link(&service, confirmation).await?;

    let password_signin = harbor_leptos::signin_with_password(
        &service,
        config,
        csrf_request.clone(),
        harbor_core::PasswordSignInInput {
            email: email.clone(),
            password: password.clone(),
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    let session_pair = first_cookie_pair(&password_signin.set_cookie)?;
    assert_current_session(&service, config, session_pair).await?;

    harbor_leptos::request_email_signin(
        &service,
        &mailer,
        config,
        csrf_request.clone(),
        email.clone(),
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let email_link = latest_link_query(&recording_mailer)?;
    let email_signin =
        harbor_leptos::handle_email_link_signin(&service, config, email_link).await?;
    let email_session_pair = match email_signin.set_cookie.as_deref() {
        Some(value) => first_cookie_pair(value)?,
        None => return Err("email signin should set a session cookie".into()),
    };
    assert_current_session(&service, config, email_session_pair).await?;

    let code = harbor_leptos::request_email_code_signin(
        &service,
        &mailer,
        config,
        csrf_request.clone(),
        email.clone(),
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let code_signin = harbor_leptos::verify_email_code(
        &service,
        config,
        csrf_request.clone(),
        harbor_core::EmailChallengeSignInInput {
            challenge_id: code.challenge_id,
            secret: SecretToken::try_new(latest_otp_code(&recording_mailer)?)?,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    let code_session_pair = first_cookie_pair(&code_signin.set_cookie)?;
    assert_current_session(&service, config, code_session_pair).await?;

    harbor_leptos::request_password_reset(
        &service,
        &mailer,
        config,
        csrf_request.clone(),
        harbor_core::RequestPasswordResetInput {
            email,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/signin")?),
        },
    )
    .await?;
    let reset_link = latest_link_query(&recording_mailer)?;
    harbor_leptos::reset_password(
        &service,
        config,
        csrf_request.clone(),
        harbor_core::ResetPasswordInput {
            challenge_id: ChallengeId::try_new(reset_link.challenge)?,
            secret: SecretToken::try_new(reset_link.token)?,
            new_password: "new correct horse battery staple".to_owned(),
        },
    )
    .await?;
    harbor_leptos::sign_out(&service, config, csrf_request).await?;
    Ok(())
}

fn smoke_email_for_run(
    smoke_email: Option<String>,
    timestamp_micros: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(email) = smoke_email else {
        return Ok(format!("demo-{timestamp_micros}@example.com"));
    };
    let Some((local, domain)) = email.split_once('@') else {
        return Err("HARBOR_HEADLESS_DEMO_SMOKE_EMAIL must contain exactly one @".into());
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err("HARBOR_HEADLESS_DEMO_SMOKE_EMAIL must be a valid email-like address".into());
    }
    Ok(format!("{local}+harbor{timestamp_micros}@{domain}"))
}

fn auth_service(
    store: SqliteAuthStore,
    hmac_key: Vec<u8>,
) -> Result<
    AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>,
    Box<dyn std::error::Error>,
> {
    Ok(AuthService::new(
        store,
        SystemClock,
        SystemSecretGenerator,
        HmacSecretKey::try_new(hmac_key)?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    ))
}
