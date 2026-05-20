//! Email delivery integrations for Harbor.
//!
//! This crate keeps provider-specific delivery outside `harbor-core` while
//! exposing a small, testable boundary for auth emails.

mod configured;
mod message;
mod recipient;
mod recording;
mod renderer;
#[cfg(feature = "email-resend")]
mod resend;
mod url;

pub use configured::{ConfiguredAuthMailer, EmailDeliveryMode};
pub use message::{AuthEmail, AuthMailer, ChallengeEmailInput, MailDelivery};
pub use recipient::EmailRecipient;
pub use recording::RecordingMailer;
pub use renderer::render_challenge_email_with_renderer;
pub use renderer::{AuthEmailRenderer, DefaultAuthEmailRenderer, escape_html};
#[cfg(feature = "email-resend")]
pub use resend::ResendMailer;
pub use url::SecretUrl;

/// Version of the `harbor-email` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
