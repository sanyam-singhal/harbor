//! Leptos integration helpers and components for Harbor.
//!
//! The crate starts with a framework-light configuration layer so server
//! function, cookie, CSRF, and component integrations share one validated
//! source of truth.

/// Version of the `harbor-leptos` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod app;
mod components;
mod config;
mod cookie;
mod csrf;
mod encoding;
mod links;
mod workflow;

pub use app::{
    Harbor, HarborBuilder, HarborLeptosContext, expect_harbor_context, provide_harbor_context,
    use_harbor_context,
};
pub use components::{
    Authenticated, EmailCodeForm, ForgotPasswordForm, ResetPasswordForm, SignOutForm, SigninForm,
    SignupForm, Unauthenticated,
};
pub(crate) use config::HarborConfigBuilder;
pub use config::{AuthRateLimits, ChallengeLifetimes, HarborConfig, PublicBaseUrl};
pub use cookie::{
    CookieDefaults, CookieName, SameSite, build_csrf_cookie, build_delete_csrf_cookie,
    build_delete_session_cookie, build_session_cookie, parse_cookie_value,
};
pub use csrf::validate_csrf_tokens;
pub use csrf::{CsrfRequest, HeaderName, issue_csrf_token, validate_csrf_from_headers};
pub(crate) use encoding::{lower_hex, percent_encode_query};
pub use links::{
    AuthLinkQuery, LinkRouteResponse, handle_confirm_email_link, handle_email_link_signin,
    handle_reset_password_link,
};
pub use workflow::{
    AuthActionResponse, EmailCodeActionResponse, SessionActionResponse, current_session,
    request_email_code_signin, request_email_signin, request_password_reset, reset_password,
    sign_out, signin_with_password, signup_with_password, verify_email_code,
};

#[cfg(feature = "axum")]
pub mod axum;
