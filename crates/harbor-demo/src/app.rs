//! Leptos UI for the Harbor demo.

use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;

use crate::auth::{CsrfField, DemoPublicConfig};

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
    view! {
        <AuthPanel title="Create account" subtitle="Password accounts require email confirmation before signin.">
            <QueryNotice/>
            <form method="post" action="/api/auth/sign-up/email">
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <label>"Password"<input name="password" type="password" autocomplete="new-password" required minlength="12"/></label>
                <button type="submit">"Create account"</button>
            </form>
            <p class="form-note">"Already verified? " <a href="/signin">"Sign in with password"</a></p>
        </AuthPanel>
    }
}

#[component]
fn SigninPage() -> impl IntoView {
    view! {
        <AuthPanel title="Sign in" subtitle="Use a verified password account, or switch to email-only auth.">
            <QueryNotice/>
            <form method="post" action="/api/auth/sign-in/email">
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <label>"Password"<input name="password" type="password" autocomplete="current-password" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Sign in"</button>
            </form>
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
    view! {
        <AuthPanel title="Magic link" subtitle="Creates or signs into an account with a secure email link.">
            <QueryNotice/>
            <form method="post" action="/api/auth/sign-in/magic-link">
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Send magic link"</button>
            </form>
        </AuthPanel>
    }
}

#[component]
fn EmailCodePage() -> impl IntoView {
    let challenge = query_value("challenge");
    view! {
        <AuthPanel title="Email OTP" subtitle="Creates or signs into an account with an 8-digit code.">
            <QueryNotice/>
            <form method="post" action="/api/auth/email-otp/send">
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Send code"</button>
            </form>
            <form method="post" action="/api/auth/email-otp/sign-in">
                <CsrfField/>
                <input name="challenge" type="hidden" value=move || challenge().unwrap_or_default()/>
                <label>"Code"<input name="code" inputmode="numeric" autocomplete="one-time-code" required minlength="8" maxlength="8"/></label>
                <input name="redirect" type="hidden" value="/account"/>
                <button type="submit">"Verify code"</button>
            </form>
        </AuthPanel>
    }
}

#[component]
fn ForgotPasswordPage() -> impl IntoView {
    view! {
        <AuthPanel title="Reset password" subtitle="Password reset is only sent for password-based accounts.">
            <QueryNotice/>
            <form method="post" action="/api/auth/password/forgot">
                <CsrfField/>
                <label>"Email"<input name="email" type="email" autocomplete="email" required/></label>
                <input name="redirect" type="hidden" value="/signin"/>
                <button type="submit">"Send reset link"</button>
            </form>
        </AuthPanel>
    }
}

#[component]
fn ResetPasswordPage() -> impl IntoView {
    let challenge = query_value("challenge");
    let token = query_value("token");
    view! {
        <AuthPanel title="Choose new password" subtitle="Submit the reset link token with a new password.">
            <QueryNotice/>
            <form method="post" action="/api/auth/password/reset">
                <CsrfField/>
                <input name="challenge" type="hidden" value=move || challenge().unwrap_or_default()/>
                <input name="token" type="hidden" value=move || token().unwrap_or_default()/>
                <label>"New password"<input name="new_password" type="password" autocomplete="new-password" required minlength="12"/></label>
                <button type="submit">"Reset password"</button>
            </form>
        </AuthPanel>
    }
}

#[component]
fn AccountPage() -> impl IntoView {
    view! {
        <AuthPanel title="Account" subtitle="This page is the post-signin landing zone for session-cookie validation.">
            <QueryNotice/>
            <p class="success">"If you arrived here from signin, the server issued a Harbor session cookie."</p>
            <form method="post" action="/api/auth/sign-out">
                <CsrfField/>
                <button type="submit">"Sign out"</button>
            </form>
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
fn QueryNotice() -> impl IntoView {
    let notice = query_value("notice");
    view! {
        {move || notice().map(|value| view! { <p class="success">{notice_text(&value)}</p> })}
    }
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
