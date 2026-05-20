//! Demo-owned Harbor auth configuration.

#[cfg(feature = "ssr")]
use axum::extract::FromRef;
#[cfg(feature = "ssr")]
use harbor::core::{ChallengePurpose, MailError};
#[cfg(feature = "ssr")]
use harbor::email::{
    AuthEmail, AuthEmailRenderer, ChallengeEmailInput, ConfiguredAuthMailer, SecretUrl, escape_html,
};
#[cfg(feature = "ssr")]
use harbor::leptos::Harbor;
#[cfg(feature = "ssr")]
use harbor::leptos::sqlx::sqlite::{SqliteHarbor, SqliteHarborService};
#[cfg(feature = "ssr")]
use harbor::sqlx::SqliteAuthStore;
#[cfg(feature = "ssr")]
use leptos::config::LeptosOptions;
use leptos::prelude::*;

/// Public labels needed while rendering the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoPublicConfig {
    /// Product name shown in the UI and auth email templates.
    pub product_name: String,
    /// Site name shown in auth email templates and UI captions.
    pub site_name: String,
}

/// CSRF hidden input for Harbor auth forms.
#[component]
pub fn CsrfField() -> impl IntoView {
    let token = issue_form_csrf().unwrap_or_default();
    view! { <input name="csrf_token" type="hidden" value=token/> }
}

/// Concrete auth service used by the demo.
#[cfg(feature = "ssr")]
pub type DemoAuthService = SqliteHarborService;

#[cfg(feature = "ssr")]
type DemoAuth = SqliteHarbor<ConfiguredAuthMailer>;

/// Server state shared with Leptos route rendering.
#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct DemoState {
    leptos_options: LeptosOptions,
    auth: DemoAuth,
    public_config: DemoPublicConfig,
}

#[cfg(feature = "ssr")]
impl DemoState {
    /// Builds demo state from environment and Leptos options.
    ///
    /// # Errors
    ///
    /// Returns an error when required environment variables are missing,
    /// configuration is invalid, SQLite cannot open, or migrations cannot run.
    pub async fn from_env(
        leptos_options: LeptosOptions,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let public_config = public_config_from_env()?;
        let auth = SqliteHarbor::from_env_with_email_renderer(DemoAuthEmailRenderer::new(
            public_config.clone(),
        ))
        .await?;
        Ok(Self {
            leptos_options,
            auth,
            public_config,
        })
    }

    /// Returns the Harbor shell.
    #[must_use]
    pub const fn harbor(&self) -> &Harbor<SqliteAuthStore, ConfiguredAuthMailer> {
        self.auth.harbor()
    }

    /// Returns the auth service.
    #[must_use]
    pub const fn service(&self) -> &DemoAuthService {
        self.auth.service()
    }

    /// Returns public rendering labels.
    #[must_use]
    pub const fn public_config(&self) -> &DemoPublicConfig {
        &self.public_config
    }

    /// Builds Harbor's mounted auth router for the demo.
    #[must_use]
    pub fn auth_router(&self) -> axum::Router {
        self.auth.axum_router()
    }
}

#[cfg(feature = "ssr")]
impl FromRef<DemoState> for LeptosOptions {
    fn from_ref(state: &DemoState) -> Self {
        state.leptos_options.clone()
    }
}

/// Provides app state to Leptos context.
#[cfg(feature = "ssr")]
pub fn provide_demo_state(state: DemoState) {
    leptos::prelude::provide_context(state.public_config().clone());
    leptos::prelude::provide_context(state);
}

/// Returns a cloned demo state from Leptos context.
#[cfg(feature = "ssr")]
#[must_use]
pub fn use_demo_state() -> Option<DemoState> {
    leptos::prelude::use_context::<DemoState>()
}

#[cfg(feature = "ssr")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoAuthEmailRenderer {
    public_config: DemoPublicConfig,
}

#[cfg(feature = "ssr")]
impl DemoAuthEmailRenderer {
    fn new(public_config: DemoPublicConfig) -> Self {
        Self { public_config }
    }

    fn subject(&self, purpose: ChallengePurpose) -> String {
        match purpose {
            ChallengePurpose::SignupConfirmation => {
                format!("Confirm your {} account", self.public_config.product_name)
            }
            ChallengePurpose::EmailSignIn => {
                format!("Sign in to {}", self.public_config.product_name)
            }
            ChallengePurpose::PasswordReset => {
                format!("Reset your {} password", self.public_config.product_name)
            }
            _ => format!("{} auth request", self.public_config.product_name),
        }
    }

    fn intro(&self, purpose: ChallengePurpose) -> String {
        match purpose {
            ChallengePurpose::SignupConfirmation => format!(
                "Complete your {} sign-up for {}.",
                self.public_config.product_name, self.public_config.site_name
            ),
            ChallengePurpose::EmailSignIn => format!(
                "Use this secure challenge to sign in to {}.",
                self.public_config.product_name
            ),
            ChallengePurpose::PasswordReset => format!(
                "Use this secure challenge to reset your {} password.",
                self.public_config.product_name
            ),
            _ => format!(
                "Use this {} challenge to continue.",
                self.public_config.product_name
            ),
        }
    }

    fn text_body(&self, input: &ChallengeEmailInput) -> String {
        let mut body = self.intro(input.purpose);
        if let Some(url) = input.action_url.as_ref() {
            body.push_str("\n\nOpen this link:\n");
            body.push_str(url.expose_secret());
        }
        if let Some(code) = input.otp_code.as_ref() {
            body.push_str("\n\nCode: ");
            body.push_str(code.expose_secret());
        }
        body.push_str("\n\nThis request expires soon. Do not share the link or code.");
        body
    }

    fn html_body(&self, input: &ChallengeEmailInput) -> String {
        let mut body = String::from(
            "<div style=\"font-family:Inter,Arial,sans-serif;line-height:1.5;color:#12201b\">",
        );
        body.push_str("<p>");
        body.push_str(&escape_html(&self.intro(input.purpose)));
        body.push_str("</p>");
        if let Some(url) = input.action_url.as_ref() {
            body.push_str("<p><a style=\"display:inline-block;padding:12px 16px;background:#155e75;color:white;text-decoration:none;border-radius:6px\" href=\"");
            body.push_str(&escape_html(url.expose_secret()));
            body.push_str("\">Continue securely</a></p>");
            body.push_str("<p style=\"font-size:13px;color:#51615c\">Or paste this link into your browser:<br>");
            body.push_str(&escape_html_url(url));
            body.push_str("</p>");
        }
        if let Some(code) = input.otp_code.as_ref() {
            body.push_str(
                "<p>Your code is <strong style=\"font-size:24px;letter-spacing:0.08em\">",
            );
            body.push_str(&escape_html(code.expose_secret()));
            body.push_str("</strong></p>");
        }
        body.push_str("<p style=\"font-size:13px;color:#51615c\">If you did not request this, ignore this email. Never share auth links or codes.</p>");
        body.push_str("</div>");
        body
    }
}

#[cfg(feature = "ssr")]
impl AuthEmailRenderer for DemoAuthEmailRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        let subject = self.subject(input.purpose);
        let text_body = self.text_body(&input);
        let html_body = self.html_body(&input);
        AuthEmail::try_new(
            input.purpose,
            input.to,
            input.challenge_id,
            subject,
            text_body,
            Some(html_body),
        )
    }
}

#[cfg(feature = "ssr")]
fn escape_html_url(url: &SecretUrl) -> String {
    escape_html(url.expose_secret())
}

#[cfg(feature = "ssr")]
fn issue_form_csrf() -> Option<String> {
    use axum::http::header::SET_COOKIE;
    use harbor::core::SystemSecretGenerator;
    use leptos::prelude::use_context;
    use leptos_axum::ResponseOptions;

    let state = use_demo_state()?;
    let csrf =
        harbor::leptos::issue_csrf_token(state.harbor().config(), &SystemSecretGenerator).ok()?;
    let cookie =
        harbor::leptos::build_csrf_cookie(state.harbor().config().cookie_defaults(), &csrf, None)
            .ok()?;
    if let Some(response) = use_context::<ResponseOptions>() {
        response.append_header(SET_COOKIE, header_value(&cookie)?);
    }
    Some(csrf.expose_secret().to_owned())
}

#[cfg(not(feature = "ssr"))]
fn issue_form_csrf() -> Option<String> {
    None
}

#[cfg(feature = "ssr")]
fn header_value(value: &str) -> Option<axum::http::HeaderValue> {
    axum::http::HeaderValue::from_str(value).ok()
}

#[cfg(feature = "ssr")]
fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_error| config_error(format!("{name} is required")))
}

#[cfg(feature = "ssr")]
fn public_config_from_env() -> Result<DemoPublicConfig, Box<dyn std::error::Error>> {
    Ok(DemoPublicConfig {
        product_name: required_env("HARBOR_PRODUCT_NAME")?,
        site_name: required_env("HARBOR_EMAIL_SITE_NAME")?,
    })
}

#[cfg(feature = "ssr")]
fn config_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}
