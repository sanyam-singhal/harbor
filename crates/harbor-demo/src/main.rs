//! Demonstration application for Harbor.

use std::{
    collections::HashMap,
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, ChallengeDelivery, ChallengeId, Clock,
    EmailChallengeSignInInput, HmacSecretKey, PasswordPolicy, PasswordSignInInput,
    PasswordSignUpInput, RedirectPath, RequestPasswordResetInput, ResetPasswordInput, SecretToken,
    SystemClock, SystemSecretGenerator,
};
use harbor_email::RecordingMailer;
use harbor_leptos::{CookieDefaults, CsrfRequest, Harbor, build_csrf_cookie, issue_csrf_token};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

const DEFAULT_DATABASE_URL: &str = "sqlite://harbor-demo.sqlite?mode=rwc";
const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:3000";
const DEFAULT_DEMO_ADDR: &str = "127.0.0.1:3000";

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
        run_recording_smoke(
            store.clone(),
            mailer.clone(),
            harbor.config(),
            settings.hmac_key.clone(),
        )
        .await?;
        println!("Demo auth smoke: ok");
    }
    if settings.run_browser_smoke {
        let service = auth_service(store, settings.hmac_key)?;
        run_browser_smoke_server(
            &settings.demo_addr,
            service,
            mailer,
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
    hmac_key: Vec<u8>,
    run_smoke: bool,
    run_browser_smoke: bool,
    demo_addr: String,
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
            run_browser_smoke: env::var("HARBOR_DEMO_BROWSER_SMOKE")
                .map(|value| value == "1" || value == "true")
                .unwrap_or(false),
            demo_addr: env::var("HARBOR_DEMO_ADDR")
                .unwrap_or_else(|_error| DEFAULT_DEMO_ADDR.to_owned()),
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
    let service = auth_service(store, hmac_key)?;
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

type DemoAuthService = AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoHttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

async fn run_browser_smoke_server(
    addr: &str,
    service: DemoAuthService,
    mailer: RecordingMailer,
    config: harbor_leptos::HarborConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr)?;
    println!("Harbor demo browser smoke listening: http://{addr}");
    for stream in listener.incoming() {
        let mut stream = stream?;
        let response = match read_http_request(&mut stream) {
            Ok(request) => handle_browser_request(request, &service, &mailer, &config).await,
            Err(error) => Ok(error_response(400, &error.to_string())),
        };
        match response {
            Ok(response) => write_http_response(&mut stream, response)?,
            Err(error) => {
                write_http_response(&mut stream, error_response(500, &error.to_string()))?
            }
        }
    }
    Ok(())
}

async fn handle_browser_request(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    mailer: &RecordingMailer,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Ok(html_response(200, Vec::new(), "ok".to_owned())),
        ("GET", "/") | ("GET", "/signup") => signup_page(config),
        ("POST", "/signup") => handle_signup(request, service, mailer, config).await,
        ("GET", "/auth/confirm-email") => handle_confirm(request, service).await,
        ("GET", "/signin") => signin_page(config, signin_message(&request)),
        ("POST", "/signin") => handle_signin(request, service, config).await,
        ("GET", "/signin/email-link") => email_link_page(config),
        ("POST", "/signin/email-link") => {
            handle_email_link_request(request, service, mailer, config).await
        }
        ("GET", "/auth/email-link") => handle_email_link(request, service, config).await,
        ("GET", "/signin/email-code") => email_code_request_page(config),
        ("POST", "/signin/email-code/request") => {
            handle_email_code_request(request, service, mailer, config).await
        }
        ("POST", "/signin/email-code/verify") => {
            handle_email_code_verify(request, service, config).await
        }
        ("GET", "/forgot-password") => forgot_password_page(config),
        ("POST", "/forgot-password") => {
            handle_forgot_password(request, service, mailer, config).await
        }
        ("GET", "/auth/reset-password") => handle_reset_password_link(request),
        ("GET", "/reset-password") => reset_password_page(request, config),
        ("POST", "/reset-password") => handle_reset_password(request, service, config).await,
        ("GET", "/account") => account_page(request, service, config).await,
        ("POST", "/signout") => handle_signout(request, service, config).await,
        _ => Ok(error_response(404, "Not found")),
    }
}

fn signup_page(
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let body = format!(
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Harbor signup</h1>",
            "<form method=\"post\" action=\"/signup\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            "<label>Email <input name=\"email\" type=\"email\" required></label>",
            "<label>Password <input name=\"password\" type=\"password\" required></label>",
            "<button type=\"submit\">Create account</button>",
            "</form></main></body></html>"
        ),
        html_escape(csrf.expose_secret())
    );
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), csrf_cookie)],
        body,
    ))
}

async fn handle_signup(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    mailer: &RecordingMailer,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let email = required_form_value(&form, "email")?.to_owned();
    let password = required_form_value(&form, "password")?.to_owned();
    let csrf = csrf_request_from_form(&request, &form);
    harbor_leptos::signup_with_password(
        service,
        mailer,
        config,
        csrf,
        PasswordSignUpInput { email, password },
    )
    .await?;
    let link_query = latest_link_query(mailer)?;
    let confirmation_href = auth_link_href("/auth/confirm-email", &link_query);
    Ok(html_response(
        200,
        Vec::new(),
        format!(
            concat!(
                "<!doctype html><html><body>",
                "<main><h1>Check your email</h1>",
                "<a data-testid=\"verification-link\" href=\"{}\">Verify email</a>",
                "</main></body></html>"
            ),
            html_escape(&confirmation_href)
        ),
    ))
}

async fn handle_confirm(
    request: DemoHttpRequest,
    service: &DemoAuthService,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let challenge = required_query_value(&request, "challenge")?.to_owned();
    let token = required_query_value(&request, "token")?.to_owned();
    let response = harbor_leptos::handle_confirm_email_link(
        service,
        harbor_leptos::AuthLinkQuery {
            challenge,
            token,
            redirect: None,
        },
    )
    .await?;
    Ok(redirect_response(
        303,
        &with_query(&response.location, "verified", "1"),
        None,
    ))
}

fn signin_page(
    config: &harbor_leptos::HarborConfig,
    message: Option<&str>,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let message_html = message
        .map(normalize_signin_message)
        .map_or_else(String::new, |value| {
            format!("<p data-testid=\"status\">{}</p>", html_escape(value))
        });
    let body = format!(
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Harbor signin</h1>{}",
            "<form method=\"post\" action=\"/signin\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            "<label>Email <input name=\"email\" type=\"email\" required></label>",
            "<label>Password <input name=\"password\" type=\"password\" required></label>",
            "<button type=\"submit\">Sign in</button>",
            "</form></main></body></html>"
        ),
        message_html,
        html_escape(csrf.expose_secret())
    );
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), csrf_cookie)],
        body,
    ))
}

async fn handle_signin(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let email = required_form_value(&form, "email")?.to_owned();
    let password = required_form_value(&form, "password")?.to_owned();
    let csrf = csrf_request_from_form(&request, &form);
    let signin = harbor_leptos::signin_with_password(
        service,
        config,
        csrf,
        PasswordSignInInput {
            email,
            password,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), signin.set_cookie)],
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Signed in</h1>",
            "<a data-testid=\"account-link\" href=\"/account\">Account</a>",
            "</main></body></html>"
        )
        .to_owned(),
    ))
}

fn email_link_page(
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    auth_email_request_page(
        config,
        "Email link signin",
        "/signin/email-link",
        "Send magic link",
    )
}

async fn handle_email_link_request(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    mailer: &RecordingMailer,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let email = required_form_value(&form, "email")?.to_owned();
    let csrf = csrf_request_from_form(&request, &form);
    harbor_leptos::request_email_signin(
        service,
        mailer,
        config,
        csrf,
        email,
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let link_query = latest_link_query(mailer)?;
    let href = auth_link_href("/auth/email-link", &link_query);
    Ok(html_response(
        200,
        Vec::new(),
        format!(
            concat!(
                "<!doctype html><html><body>",
                "<main><h1>Check your email</h1>",
                "<a data-testid=\"email-link\" href=\"{}\">Sign in by email</a>",
                "</main></body></html>"
            ),
            html_escape(&href)
        ),
    ))
}

async fn handle_email_link(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let challenge = required_query_value(&request, "challenge")?.to_owned();
    let token = required_query_value(&request, "token")?.to_owned();
    let response = harbor_leptos::handle_email_link_signin(
        service,
        config,
        harbor_leptos::AuthLinkQuery {
            challenge,
            token,
            redirect: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    Ok(redirect_response(
        303,
        &response.location,
        response.set_cookie,
    ))
}

fn email_code_request_page(
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    auth_email_request_page(
        config,
        "Email code signin",
        "/signin/email-code/request",
        "Send code",
    )
}

async fn handle_email_code_request(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    mailer: &RecordingMailer,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let email = required_form_value(&form, "email")?.to_owned();
    let csrf = csrf_request_from_form(&request, &form);
    let challenge = harbor_leptos::request_email_code_signin(
        service,
        mailer,
        config,
        csrf,
        email,
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let code = latest_otp_code(mailer)?;
    email_code_verify_page(config, challenge.challenge_id.as_str(), &code)
}

fn email_code_verify_page(
    config: &harbor_leptos::HarborConfig,
    challenge_id: &str,
    code: &str,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let body = format!(
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Enter code</h1>",
            "<p data-testid=\"recorded-code\">{}</p>",
            "<form method=\"post\" action=\"/signin/email-code/verify\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            "<input type=\"hidden\" name=\"challenge\" value=\"{}\">",
            "<label>Code <input name=\"code\" inputmode=\"numeric\" required></label>",
            "<button type=\"submit\">Verify code</button>",
            "</form></main></body></html>"
        ),
        html_escape(code),
        html_escape(csrf.expose_secret()),
        html_escape(challenge_id)
    );
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), csrf_cookie)],
        body,
    ))
}

async fn handle_email_code_verify(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let csrf = csrf_request_from_form(&request, &form);
    let signin = harbor_leptos::verify_email_code(
        service,
        config,
        csrf,
        EmailChallengeSignInInput {
            challenge_id: ChallengeId::try_new(required_form_value(&form, "challenge")?)?,
            secret: SecretToken::try_new(required_form_value(&form, "code")?)?,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), signin.set_cookie)],
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Signed in</h1>",
            "<a data-testid=\"account-link\" href=\"/account\">Account</a>",
            "</main></body></html>"
        )
        .to_owned(),
    ))
}

fn forgot_password_page(
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    auth_email_request_page(
        config,
        "Forgot password",
        "/forgot-password",
        "Send reset link",
    )
}

async fn handle_forgot_password(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    mailer: &RecordingMailer,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let email = required_form_value(&form, "email")?.to_owned();
    let csrf = csrf_request_from_form(&request, &form);
    harbor_leptos::request_password_reset(
        service,
        mailer,
        config,
        csrf,
        RequestPasswordResetInput {
            email,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/signin")?),
        },
    )
    .await?;
    let link_query = latest_link_query(mailer)?;
    let href = auth_link_href("/auth/reset-password", &link_query);
    Ok(html_response(
        200,
        Vec::new(),
        format!(
            concat!(
                "<!doctype html><html><body>",
                "<main><h1>Check your email</h1>",
                "<a data-testid=\"reset-link\" href=\"{}\">Reset password</a>",
                "</main></body></html>"
            ),
            html_escape(&href)
        ),
    ))
}

fn handle_reset_password_link(
    request: DemoHttpRequest,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let response = harbor_leptos::handle_reset_password_link(auth_query_from_request(&request)?)?;
    Ok(redirect_response(303, &response.location, None))
}

fn reset_password_page(
    request: DemoHttpRequest,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let challenge = required_query_value(&request, "challenge")?;
    let token = required_query_value(&request, "token")?;
    let body = format!(
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Reset password</h1>",
            "<form method=\"post\" action=\"/reset-password\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            "<input type=\"hidden\" name=\"challenge\" value=\"{}\">",
            "<input type=\"hidden\" name=\"token\" value=\"{}\">",
            "<label>New password <input name=\"password\" type=\"password\" required></label>",
            "<button type=\"submit\">Reset password</button>",
            "</form></main></body></html>"
        ),
        html_escape(csrf.expose_secret()),
        html_escape(challenge),
        html_escape(token)
    );
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), csrf_cookie)],
        body,
    ))
}

async fn handle_reset_password(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let csrf = csrf_request_from_form(&request, &form);
    harbor_leptos::reset_password(
        service,
        config,
        csrf,
        ResetPasswordInput {
            challenge_id: ChallengeId::try_new(required_form_value(&form, "challenge")?)?,
            secret: SecretToken::try_new(required_form_value(&form, "token")?)?,
            new_password: required_form_value(&form, "password")?.to_owned(),
        },
    )
    .await?;
    Ok(html_response(
        200,
        Vec::new(),
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>Password reset</h1>",
            "<a data-testid=\"signin-link\" href=\"/signin\">Sign in</a>",
            "</main></body></html>"
        )
        .to_owned(),
    ))
}

async fn account_page(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let current = harbor_leptos::current_session(
        service,
        config,
        request.headers.get("cookie").map(String::as_str),
    )
    .await?;
    let (status, headers, body) = if current.is_some() {
        let csrf = issue_csrf_token(&SystemSecretGenerator)?;
        let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
        (
            200,
            vec![("Set-Cookie".to_owned(), csrf_cookie)],
            format!(
                concat!(
                    "<!doctype html><html><body>",
                    "<main><h1 data-testid=\"account-status\">Signed in</h1>",
                    "<form method=\"post\" action=\"/signout\">",
                    "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
                    "<button type=\"submit\">Sign out</button>",
                    "</form></main></body></html>"
                ),
                html_escape(csrf.expose_secret())
            ),
        )
    } else {
        (
            401,
            Vec::new(),
            concat!(
                "<!doctype html><html><body>",
                "<main><h1 data-testid=\"account-status\">Signed out</h1>",
                "</main></body></html>"
            )
            .to_owned(),
        )
    };
    Ok(html_response(status, headers, body))
}

async fn handle_signout(
    request: DemoHttpRequest,
    service: &DemoAuthService,
    config: &harbor_leptos::HarborConfig,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let form = parse_form(&request.body)?;
    let csrf = csrf_request_from_form(&request, &form);
    let delete_cookie = harbor_leptos::sign_out(service, config, csrf).await?;
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), delete_cookie)],
        concat!(
            "<!doctype html><html><body>",
            "<main><h1 data-testid=\"account-status\">Signed out</h1>",
            "</main></body></html>"
        )
        .to_owned(),
    ))
}

fn csrf_request_from_form(
    request: &DemoHttpRequest,
    form: &HashMap<String, String>,
) -> CsrfRequest {
    CsrfRequest {
        cookie_header: request.headers.get("cookie").cloned(),
        csrf_header: form.get("csrf").cloned(),
    }
}

fn auth_email_request_page(
    config: &harbor_leptos::HarborConfig,
    heading: &str,
    action: &str,
    button: &str,
) -> Result<DemoHttpResponse, Box<dyn std::error::Error>> {
    let csrf = issue_csrf_token(&SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(config.cookie_defaults(), &csrf, None)?;
    let body = format!(
        concat!(
            "<!doctype html><html><body>",
            "<main><h1>{}</h1>",
            "<form method=\"post\" action=\"{}\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            "<label>Email <input name=\"email\" type=\"email\" required></label>",
            "<button type=\"submit\">{}</button>",
            "</form></main></body></html>"
        ),
        html_escape(heading),
        html_escape(action),
        html_escape(csrf.expose_secret()),
        html_escape(button)
    );
    Ok(html_response(
        200,
        vec![("Set-Cookie".to_owned(), csrf_cookie)],
        body,
    ))
}

fn signin_message(request: &DemoHttpRequest) -> Option<&str> {
    request.query.get("verified").and_then(
        |value| {
            if value == "1" { Some("verified") } else { None }
        },
    )
}

fn normalize_signin_message(message: &str) -> &str {
    match message {
        "verified" => "Email verified. Sign in to continue.",
        _ => message,
    }
}

fn auth_query_from_request(
    request: &DemoHttpRequest,
) -> Result<harbor_leptos::AuthLinkQuery, Box<dyn std::error::Error>> {
    Ok(harbor_leptos::AuthLinkQuery {
        challenge: required_query_value(request, "challenge")?.to_owned(),
        token: required_query_value(request, "token")?.to_owned(),
        redirect: None,
    })
}

fn auth_link_href(path: &str, query: &harbor_leptos::AuthLinkQuery) -> String {
    format!(
        "{}?challenge={}&token={}",
        path,
        url_component(&query.challenge),
        url_component(&query.token)
    )
}

fn with_query(path: &str, name: &str, value: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!(
        "{}{}{}={}",
        path,
        separator,
        url_component(name),
        url_component(value)
    )
}

fn required_form_value<'a>(
    form: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    form.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing form field: {name}").into())
}

fn required_query_value<'a>(
    request: &'a DemoHttpRequest,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    request
        .query
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing query field: {name}").into())
}

fn read_http_request(
    stream: &mut TcpStream,
) -> Result<DemoHttpRequest, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err("connection closed before request headers".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > 128 * 1024 {
            return Err("request is too large".into());
        }
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
    };
    let headers_text = String::from_utf8(bytes[..header_end].to_vec())?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or("missing method")?.to_owned();
    let target = request_parts.next().ok_or("missing target")?;
    let (path, query) = parse_target(target)?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body_start = header_end + 4;
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err("connection closed before request body".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > 128 * 1024 {
            return Err("request is too large".into());
        }
    }
    let body_end = body_start + content_length;
    let body = String::from_utf8(bytes[body_start..body_end].to_vec())?;
    Ok(DemoHttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_target(
    target: &str,
) -> Result<(String, HashMap<String, String>), Box<dyn std::error::Error>> {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), parse_form(query)?),
        None => (target.to_owned(), HashMap::new()),
    };
    Ok((path, query))
}

fn parse_form(body: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    if body.is_empty() {
        return Ok(values);
    }
    for pair in body.split('&') {
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        values.insert(percent_decode_form(name)?, percent_decode_form(value)?);
    }
    Ok(values)
}

fn percent_decode_form(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'+' => {
                bytes.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= input.len() {
                    return Err("truncated percent encoding".into());
                }
                let high = hex_value(input[index + 1]).ok_or("invalid percent encoding")?;
                let low = hex_value(input[index + 2]).ok_or("invalid percent encoding")?;
                bytes.push((high << 4) | low);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                encoded.push('%');
                encoded.push(hex_digit(byte >> 4));
                encoded.push(hex_digit(byte & 0x0f));
            }
        }
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'A' + (value - 10)),
        _ => '0',
    }
}

fn html_response(status: u16, headers: Vec<(String, String)>, body: String) -> DemoHttpResponse {
    DemoHttpResponse {
        status,
        headers,
        body,
    }
}

fn error_response(status: u16, message: &str) -> DemoHttpResponse {
    html_response(
        status,
        Vec::new(),
        format!(
            "<!doctype html><html><body><main><h1>{}</h1></main></body></html>",
            html_escape(message)
        ),
    )
}

fn redirect_response(status: u16, location: &str, set_cookie: Option<String>) -> DemoHttpResponse {
    let mut headers = vec![
        ("Location".to_owned(), location.to_owned()),
        ("Referrer-Policy".to_owned(), "no-referrer".to_owned()),
    ];
    if let Some(cookie) = set_cookie {
        headers.push(("Set-Cookie".to_owned(), cookie));
    }
    html_response(status, headers, String::new())
}

fn write_http_response(
    stream: &mut TcpStream,
    response: DemoHttpResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match response.status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    );
    for (name, value) in response.headers {
        head.push_str(&name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(response.body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::new();
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

fn latest_otp_code(mailer: &RecordingMailer) -> Result<String, Box<dyn std::error::Error>> {
    let recorded = mailer.recorded()?;
    let email = match recorded.last() {
        Some(email) => email,
        None => return Err("recording mailer should contain an auth email".into()),
    };
    let mut lines = email.text_body().lines();
    while let Some(line) = lines.next() {
        if line == "Use this code:" {
            return lines
                .next()
                .map(str::to_owned)
                .ok_or_else(|| "auth email should contain an OTP code".into());
        }
    }
    Err("auth email should contain an OTP code".into())
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
