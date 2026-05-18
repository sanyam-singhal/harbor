//! Demonstration application for Harbor.

use std::env;

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, ChallengeDelivery, ChallengeId, Clock,
    HmacSecretKey, PasswordPolicy, RedirectPath, SecretToken, SystemClock, SystemSecretGenerator,
};
use harbor_email::RecordingMailer;
use harbor_leptos::{CookieDefaults, CsrfRequest, Harbor, build_csrf_cookie, issue_csrf_token};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

const DEFAULT_DATABASE_URL: &str = "sqlite://harbor-demo.sqlite?mode=rwc";
const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = DemoSettings::from_env();
    let store = SqliteAuthStore::connect_and_migrate(
        &settings.database_url,
        sqlite_options_for_url(&settings.database_url),
    )
    .await?;
    let mailer = RecordingMailer::new();
    let harbor = Harbor::builder()
        .with_store(store.clone())
        .with_mailer(mailer.clone())
        .with_public_base_url(settings.public_base_url.clone())?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(settings.hmac_key.clone())?
        .finish()?;

    println!(
        "Harbor demo initialized: base_url={}, session_cookie={}",
        harbor.config().public_base_url(),
        harbor
            .config()
            .cookie_defaults()
            .session_cookie_name()
            .as_str()
    );
    println!("Demo mail mode: recording");
    if settings.run_smoke {
        run_recording_smoke(store, mailer, harbor.config(), settings.hmac_key).await?;
        println!("Demo auth smoke: ok");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoSettings {
    database_url: String,
    public_base_url: String,
    hmac_key: Vec<u8>,
    run_smoke: bool,
}

impl DemoSettings {
    fn from_env() -> Self {
        Self {
            database_url: env::var("HARBOR_DATABASE_URL")
                .unwrap_or_else(|_error| DEFAULT_DATABASE_URL.to_owned()),
            public_base_url: env::var("HARBOR_PUBLIC_BASE_URL")
                .unwrap_or_else(|_error| DEFAULT_PUBLIC_BASE_URL.to_owned()),
            hmac_key: env::var("HARBOR_HMAC_KEY")
                .map(|value| value.into_bytes())
                .unwrap_or_else(|_error| vec![42; 32]),
            run_smoke: env::var("HARBOR_DEMO_SMOKE")
                .map(|value| value == "1" || value == "true")
                .unwrap_or(false),
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

async fn run_recording_smoke(
    store: SqliteAuthStore,
    mailer: RecordingMailer,
    config: &harbor_leptos::HarborConfig,
    hmac_key: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = AuthService::new(
        store,
        SystemClock,
        SystemSecretGenerator,
        HmacSecretKey::try_new(hmac_key)?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let csrf_cookie_pair = first_cookie_pair(&csrf_cookie)?;
    let csrf_request = CsrfRequest {
        cookie_header: Some(csrf_cookie_pair.to_owned()),
        csrf_header: Some(csrf.expose_secret().to_owned()),
    };
    let email = format!("demo-{}@example.com", SystemClock.now().as_i64());
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
    let confirmation = latest_link_query(&mailer)?;
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
    let email_link = latest_link_query(&mailer)?;
    let email_signin =
        harbor_leptos::handle_email_link_signin(&service, config, email_link).await?;
    let email_session_pair = match email_signin.set_cookie.as_deref() {
        Some(value) => first_cookie_pair(value)?,
        None => return Err("email signin should set a session cookie".into()),
    };
    assert_current_session(&service, config, email_session_pair).await?;

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
    let reset_link = latest_link_query(&mailer)?;
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

async fn assert_current_session(
    service: &AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>,
    config: &harbor_leptos::HarborConfig,
    cookie_pair: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let current = harbor_leptos::current_session(service, config, Some(cookie_pair)).await?;
    if current.is_some() {
        Ok(())
    } else {
        Err("current session should exist".into())
    }
}

fn first_cookie_pair(set_cookie: &str) -> Result<&str, Box<dyn std::error::Error>> {
    match set_cookie.split(';').next() {
        Some(value) => Ok(value),
        None => Err("set-cookie value should contain a cookie pair".into()),
    }
}

fn latest_link_query(
    mailer: &RecordingMailer,
) -> Result<harbor_leptos::AuthLinkQuery, Box<dyn std::error::Error>> {
    let recorded = mailer.recorded()?;
    let email = match recorded.last() {
        Some(email) => email,
        None => return Err("recording mailer should contain an auth email".into()),
    };
    let link = email
        .text_body()
        .lines()
        .find(|line| line.starts_with("http://") || line.starts_with("https://"));
    let link = match link {
        Some(link) => link,
        None => return Err("auth email should contain a link".into()),
    };
    parse_link_query(link)
}

fn parse_link_query(
    link: &str,
) -> Result<harbor_leptos::AuthLinkQuery, Box<dyn std::error::Error>> {
    let query = match link.split_once('?') {
        Some((_path, query)) => query,
        None => return Err("auth link should contain a query".into()),
    };
    let mut challenge = None;
    let mut token = None;
    for part in query.split('&') {
        if let Some((name, value)) = part.split_once('=') {
            match name {
                "challenge" => challenge = Some(value.to_owned()),
                "token" => token = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    let challenge = match challenge {
        Some(value) => value,
        None => return Err("auth link should include challenge".into()),
    };
    let token = match token {
        Some(value) => value,
        None => return Err("auth link should include token".into()),
    };
    Ok(harbor_leptos::AuthLinkQuery {
        challenge,
        token,
        redirect: None,
    })
}
