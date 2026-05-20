//! Common imports for Leptos applications using Harbor.

pub use crate::core::{
    AuthError, AuthErrorCode, AuthService, ChallengeDelivery, ChallengeId, ConfigError,
    ConfigErrorCode, CurrentSession, EmailChallengeSignInInput, HmacSecretKey, MailError,
    MailErrorCode, PasswordSignInInput, PasswordSignUpInput, RedirectPath,
    RequestPasswordResetInput, ResetPasswordInput, SecretToken, StoreError, StoreErrorCode,
};
pub use crate::email::{
    AuthEmail, AuthEmailRenderer, AuthMailer, ChallengeEmailInput, ConfiguredAuthMailer,
    DefaultAuthEmailRenderer, EmailDeliveryMode, MailDelivery, RecordingMailer, SecretUrl,
};

#[cfg(feature = "resend")]
pub use crate::email::ResendMailer;

#[cfg(feature = "leptos")]
pub use crate::leptos::{
    AuthActionResponse, AuthLinkQuery, CookieDefaults, CsrfRequest, EmailCodeActionResponse,
    Harbor, HarborBuilder, HarborConfig, LinkRouteResponse, PublicBaseUrl, SessionActionResponse,
    build_csrf_cookie, build_delete_session_cookie, build_session_cookie, current_session,
    handle_confirm_email_link, handle_email_link_signin, handle_reset_password_link,
    issue_csrf_token, request_email_code_signin, request_email_signin, request_password_reset,
    reset_password, sign_out, signin_with_password, signup_with_password, verify_email_code,
};

#[cfg(all(feature = "leptos", feature = "sqlite"))]
pub use crate::leptos::sqlx::sqlite::{
    HarborSetupError, SqliteHarbor, SqliteHarborBuilder, SqliteHarborService,
};

#[cfg(feature = "sqlite")]
pub use crate::sqlx::{SqliteAuthStore, SqliteStoreOptions};
