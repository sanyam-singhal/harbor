//! Leptos UI and server functions for the Harbor demo.

use leptos::form::ActionForm;
use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;

#[cfg(feature = "ssr")]
use harbor::{core as harbor_core, leptos as harbor_leptos};

/// Public labels needed while rendering the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoPublicConfig {
    /// Product name shown in the UI and auth email templates.
    pub product_name: String,
    /// Site name shown in auth email templates and UI captions.
    pub site_name: String,
}

/// Renders the outer HTML document for SSR.
#[must_use]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

/// Root Leptos application.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Stylesheet id="leptos" href="/pkg/harbor-demo.css"/>
        <Title text=move || format!("{} auth demo", product_name())/>
        <Router>
            <div class="app-shell">
                <Header/>
                <main>
                    <Routes fallback=NotFound>
                        <Route path=path!("") view=HomePage/>
                        <Route path=path!("/signup") view=SignupPage/>
                        <Route path=path!("/signin") view=SigninPage/>
                        <Route path=path!("/signin/email-link") view=EmailLinkPage/>
                        <Route path=path!("/signin/email-code") view=EmailCodePage/>
                        <Route path=path!("/forgot-password") view=ForgotPasswordPage/>
                        <Route path=path!("/reset-password") view=ResetPasswordPage/>
                        <Route path=path!("/account") view=AccountPage/>
                    </Routes>
                </main>
            </div>
        </Router>
    }
}

#[component]
fn Header() -> impl IntoView {
    view! {
        <header class="topbar">
            <a class="brand" href="/">
                <span class="brand-mark">"H"</span>
                <span>{move || product_name()}</span>
            </a>
            <nav>
                <a href="/signup">"Sign up"</a>
                <a href="/signin">"Sign in"</a>
                <a href="/account">"Account"</a>
            </nav>
        </header>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <section class="hero">
            <div class="hero-copy">
                <p class="eyebrow">"Email auth for Leptos"</p>
                <h1>{move || format!("Dogfood {} email authentication", product_name())}</h1>
                <p>
                    "This deployed app exercises password signup, email confirmation, password signin, magic links, OTP codes, password reset, session cookies, CSRF protection, SQLite storage, and Resend delivery."
                </p>
                <div class="actions">
                    <a class="button primary" href="/signup">"Create account"</a>
                    <a class="button secondary" href="/signin/email-link">"Use magic link"</a>
                </div>
            </div>
            <div class="status-panel">
                <h2>"v0.1 auth surface"</h2>
                <ul>
                    <li>"Email + password"</li>
                    <li>"Email confirmation"</li>
                    <li>"Email magic link"</li>
                    <li>"Email OTP"</li>
                    <li>"Forgot password"</li>
                </ul>
            </div>
        </section>
    }
}

#[component]
fn SignupPage() -> impl IntoView {
    let action = ServerAction::<Signup>::new();
    view! {
        <AuthPanel title="Create account" subtitle="Password accounts require email confirmation before signin.">
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <label>"Password"<input name="password" type="password" autocomplete="new-password" required minlength="12"/></label>
                <button type="submit">"Create account"</button>
            </ActionForm>
            <p class="form-note">"Already verified? " <a href="/signin">"Sign in with password"</a></p>
        </AuthPanel>
    }
}

#[component]
fn SigninPage() -> impl IntoView {
    let action = ServerAction::<SigninPassword>::new();
    view! {
        <AuthPanel title="Sign in" subtitle="Use a verified password account, or switch to email-only auth.">
            <QueryNotice/>
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <label>"Password"<input name="password" type="password" autocomplete="current-password" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Sign in"</button>
            </ActionForm>
            <div class="link-row">
                <a href="/signin/email-link">"Magic link"</a>
                <a href="/signin/email-code">"OTP code"</a>
                <a href="/forgot-password">"Forgot password"</a>
            </div>
        </AuthPanel>
    }
}

#[component]
fn EmailLinkPage() -> impl IntoView {
    let action = ServerAction::<RequestEmailLink>::new();
    view! {
        <AuthPanel title="Magic link" subtitle="Creates or signs into an account with a secure email link.">
            <QueryNotice/>
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Send magic link"</button>
            </ActionForm>
        </AuthPanel>
    }
}

#[component]
fn EmailCodePage() -> impl IntoView {
    let request = ServerAction::<RequestEmailCode>::new();
    let verify = ServerAction::<VerifyEmailCode>::new();
    let challenge = query_value("challenge");
    view! {
        <AuthPanel title="Email OTP" subtitle="Creates or signs into an account with an 8-digit code.">
            <QueryNotice/>
            <ActionMessage action=request/>
            <ActionMessage action=verify/>
            <ActionForm action=request>
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Send code"</button>
            </ActionForm>
            <ActionForm action=verify>
                <CsrfField/>
                <input name="challenge" type="hidden" value=move || challenge().unwrap_or_default()/>
                <label>"Code"<input name="code" inputmode="numeric" autocomplete="one-time-code" required minlength="8" maxlength="8"/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Verify code"</button>
            </ActionForm>
        </AuthPanel>
    }
}

#[component]
fn ForgotPasswordPage() -> impl IntoView {
    let action = ServerAction::<RequestPasswordReset>::new();
    view! {
        <AuthPanel title="Reset password" subtitle="Password reset is only sent for password-based accounts.">
            <QueryNotice/>
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/signin"/>
                <button type="submit">"Send reset link"</button>
            </ActionForm>
        </AuthPanel>
    }
}

#[component]
fn ResetPasswordPage() -> impl IntoView {
    let action = ServerAction::<ResetPassword>::new();
    let challenge = query_value("challenge");
    let token = query_value("token");
    view! {
        <AuthPanel title="Choose new password" subtitle="Submit the reset link token with a new password.">
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <input name="challenge" type="hidden" value=move || challenge().unwrap_or_default()/>
                <input name="token" type="hidden" value=move || token().unwrap_or_default()/>
                <label>"New password"<input name="new_password" type="password" autocomplete="new-password" required minlength="12"/></label>
                <button type="submit">"Reset password"</button>
            </ActionForm>
        </AuthPanel>
    }
}

#[component]
fn AccountPage() -> impl IntoView {
    let action = ServerAction::<SignOut>::new();
    view! {
        <AuthPanel title="Account" subtitle="This page is the post-signin landing zone for session-cookie validation.">
            <QueryNotice/>
            <p class="success">"If you arrived here from signin, the server issued a Harbor session cookie."</p>
            <ActionMessage action/>
            <ActionForm action>
                <CsrfField/>
                <button type="submit">"Sign out"</button>
            </ActionForm>
        </AuthPanel>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <section class="panel">
            <h1>"Not found"</h1>
            <p>"The requested demo route does not exist."</p>
            <a class="button secondary" href="/">"Back home"</a>
        </section>
    }
}

#[component]
fn AuthPanel(
    #[prop(into)] title: String,
    #[prop(into)] subtitle: String,
    children: Children,
) -> impl IntoView {
    view! {
        <section class="auth-layout">
            <div class="panel">
                <p class="eyebrow">{move || site_name()}</p>
                <h1>{title}</h1>
                <p class="muted">{subtitle}</p>
                {children()}
            </div>
        </section>
    }
}

#[component]
fn CsrfField() -> impl IntoView {
    let token = issue_form_csrf().unwrap_or_default();
    view! { <input name="csrf_token" type="hidden" value=token/> }
}

#[component]
fn QueryNotice() -> impl IntoView {
    let notice = query_value("notice");
    view! {
        {move || notice().map(|value| view! { <p class="success">{notice_text(&value)}</p> })}
    }
}

#[component]
fn ActionMessage<T>(action: ServerAction<T>) -> impl IntoView
where
    T: leptos::server_fn::ServerFn + Clone + Send + Sync + 'static,
    T::Output: std::fmt::Display + Send + Sync + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    let value = action.value();
    view! {
        {move || {
            value.with(|value| value.as_ref().map(|result| match result {
                Ok(message) => view! { <p class="success">{message.to_string()}</p> }.into_any(),
                Err(error) => view! { <p class="error">{error.to_string()}</p> }.into_any(),
            }))
        }}
    }
}

#[server]
async fn signup(
    email: String,
    password: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    harbor_leptos::signup_with_password(
        state.service(),
        state.harbor().mailer(),
        state.harbor().config(),
        csrf,
        harbor_core::PasswordSignUpInput { email, password },
    )
    .await
    .map_err(auth_error)?;
    leptos_axum::redirect("/signin?notice=check-email");
    Ok("Check your email to confirm the account.".to_owned())
}

#[server]
async fn signin_password(
    email: String,
    password: String,
    redirect: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let redirect_path = harbor_core::RedirectPath::try_new(redirect).map_err(input_error)?;
    let response = harbor_leptos::signin_with_password(
        state.service(),
        state.harbor().config(),
        csrf,
        harbor_core::PasswordSignInInput {
            email,
            password,
            redirect_path: Some(redirect_path),
        },
    )
    .await
    .map_err(auth_error)?;
    append_set_cookie(&response.set_cookie)?;
    leptos_axum::redirect(
        response
            .redirect_path
            .as_ref()
            .map_or("/account", harbor_core::RedirectPath::as_str),
    );
    Ok("Signed in.".to_owned())
}

#[server]
async fn request_email_link(
    email: String,
    redirect: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let redirect_path = harbor_core::RedirectPath::try_new(redirect).map_err(input_error)?;
    harbor_leptos::request_email_signin(
        state.service(),
        state.harbor().mailer(),
        state.harbor().config(),
        csrf,
        email,
        Some(redirect_path),
    )
    .await
    .map_err(auth_error)?;
    leptos_axum::redirect("/signin/email-link?notice=check-email");
    Ok("Check your email for a magic link.".to_owned())
}

#[server]
async fn request_email_code(
    email: String,
    redirect: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let redirect_path = harbor_core::RedirectPath::try_new(redirect).map_err(input_error)?;
    let response = harbor_leptos::request_email_code_signin(
        state.service(),
        state.harbor().mailer(),
        state.harbor().config(),
        csrf,
        email,
        Some(redirect_path),
    )
    .await
    .map_err(auth_error)?;
    leptos_axum::redirect(&format!(
        "/signin/email-code?notice=check-email&challenge={}",
        response.challenge_id.as_str()
    ));
    Ok("Check your email for an OTP code.".to_owned())
}

#[server]
async fn verify_email_code(
    challenge: String,
    code: String,
    redirect: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let redirect_path = harbor_core::RedirectPath::try_new(redirect).map_err(input_error)?;
    let response = harbor_leptos::verify_email_code(
        state.service(),
        state.harbor().config(),
        csrf,
        harbor_core::EmailChallengeSignInInput {
            challenge_id: harbor_core::ChallengeId::try_new(challenge).map_err(input_error)?,
            secret: harbor_core::SecretToken::try_new(code).map_err(input_error)?,
            redirect_path: Some(redirect_path),
        },
    )
    .await
    .map_err(auth_error)?;
    append_set_cookie(&response.set_cookie)?;
    leptos_axum::redirect(
        response
            .redirect_path
            .as_ref()
            .map_or("/account", harbor_core::RedirectPath::as_str),
    );
    Ok("Signed in.".to_owned())
}

#[server]
async fn request_password_reset(
    email: String,
    redirect: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let redirect_path = harbor_core::RedirectPath::try_new(redirect).map_err(input_error)?;
    harbor_leptos::request_password_reset(
        state.service(),
        state.harbor().mailer(),
        state.harbor().config(),
        csrf,
        harbor_core::RequestPasswordResetInput {
            email,
            delivery: harbor_core::ChallengeDelivery::MagicLink,
            redirect_path: Some(redirect_path),
        },
    )
    .await
    .map_err(auth_error)?;
    leptos_axum::redirect("/forgot-password?notice=check-email");
    Ok("If eligible, a reset link has been sent.".to_owned())
}

#[server]
async fn reset_password(
    challenge: String,
    token: String,
    new_password: String,
    csrf_token: String,
) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    harbor_leptos::reset_password(
        state.service(),
        state.harbor().config(),
        csrf,
        harbor_core::ResetPasswordInput {
            challenge_id: harbor_core::ChallengeId::try_new(challenge).map_err(input_error)?,
            secret: harbor_core::SecretToken::try_new(token).map_err(input_error)?,
            new_password,
        },
    )
    .await
    .map_err(auth_error)?;
    leptos_axum::redirect("/signin?notice=password-reset");
    Ok("Password reset.".to_owned())
}

#[server]
async fn sign_out(csrf_token: String) -> Result<String, ServerFnError> {
    let state = demo_state()?;
    let csrf = csrf_request(csrf_token).await?;
    let delete_cookie = harbor_leptos::sign_out(state.service(), state.harbor().config(), csrf)
        .await
        .map_err(auth_error)?;
    append_set_cookie(&delete_cookie)?;
    leptos_axum::redirect("/signin?notice=signed-out");
    Ok("Signed out.".to_owned())
}

fn product_name() -> String {
    public_config()
        .map(|config| config.product_name)
        .unwrap_or_default()
}

fn site_name() -> String {
    public_config()
        .map(|config| config.site_name)
        .unwrap_or_default()
}

fn public_config() -> Option<DemoPublicConfig> {
    leptos::prelude::use_context::<DemoPublicConfig>()
}

fn query_value(key: &'static str) -> impl Fn() -> Option<String> + Copy {
    let query = use_query_map();
    move || query.with(|params| params.get(key))
}

fn notice_text(value: &str) -> &'static str {
    match value {
        "check-email" => "Check your email to continue.",
        "password-reset" => "Password reset. Sign in with your new password.",
        "signed-out" => "Signed out.",
        "verified" => "Email verified. Sign in to continue.",
        _ => "Request complete.",
    }
}

#[cfg(feature = "ssr")]
fn issue_form_csrf() -> Result<String, ServerFnError> {
    use axum::http::header::SET_COOKIE;
    use harbor::core::SystemSecretGenerator;
    use leptos::prelude::use_context;
    use leptos_axum::ResponseOptions;

    let state = demo_state()?;
    let csrf = harbor_leptos::issue_csrf_token(state.harbor().config(), &SystemSecretGenerator)
        .map_err(auth_error)?;
    let cookie =
        harbor_leptos::build_csrf_cookie(state.harbor().config().cookie_defaults(), &csrf, None)
            .map_err(config_error)?;
    if let Some(response) = use_context::<ResponseOptions>() {
        response.append_header(SET_COOKIE, header_value(&cookie)?);
    }
    Ok(csrf.expose_secret().to_owned())
}

#[cfg(not(feature = "ssr"))]
fn issue_form_csrf() -> Result<String, ServerFnError> {
    Ok(String::new())
}

#[cfg(feature = "ssr")]
async fn csrf_request(csrf_token: String) -> Result<harbor_leptos::CsrfRequest, ServerFnError> {
    use axum::http::HeaderMap;
    use axum::http::header::{COOKIE, USER_AGENT};

    let headers: HeaderMap = leptos_axum::extract().await?;
    let cookie_header = headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let rate_limit_key = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .or_else(|| headers.get(USER_AGENT))
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Ok(harbor_leptos::CsrfRequest {
        cookie_header,
        csrf_header: Some(csrf_token),
        rate_limit_key,
    })
}

#[cfg(feature = "ssr")]
fn append_set_cookie(value: &str) -> Result<(), ServerFnError> {
    use axum::http::header::SET_COOKIE;
    use leptos::prelude::use_context;
    use leptos_axum::ResponseOptions;

    let Some(response) = use_context::<ResponseOptions>() else {
        return Err(ServerFnError::ServerError(
            "missing response context".to_owned(),
        ));
    };
    response.append_header(SET_COOKIE, header_value(value)?);
    Ok(())
}

#[cfg(feature = "ssr")]
fn header_value(value: &str) -> Result<axum::http::HeaderValue, ServerFnError> {
    axum::http::HeaderValue::from_str(value)
        .map_err(|_error| ServerFnError::ServerError("invalid response header".to_owned()))
}

#[cfg(feature = "ssr")]
fn demo_state() -> Result<crate::auth::DemoState, ServerFnError> {
    crate::auth::use_demo_state()
        .ok_or_else(|| ServerFnError::ServerError("missing demo state".to_owned()))
}

#[cfg(feature = "ssr")]
fn auth_error(error: harbor_core::AuthError) -> ServerFnError {
    ServerFnError::ServerError(error.code().as_str().to_owned())
}

#[cfg(feature = "ssr")]
fn config_error(error: harbor_core::ConfigError) -> ServerFnError {
    ServerFnError::ServerError(error.code().as_str().to_owned())
}

#[cfg(feature = "ssr")]
fn input_error<E>(_error: E) -> ServerFnError {
    ServerFnError::ServerError("invalid input".to_owned())
}
