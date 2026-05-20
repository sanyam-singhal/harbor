use harbor_core::{MailError, MailErrorCode};

use crate::{AuthEmail, AuthMailer, MailDelivery, RecordingMailer};

#[cfg(feature = "email-resend")]
use crate::ResendMailer;

/// Email delivery backend selected by application configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmailDeliveryMode {
    /// Record emails in memory for local tests and smoke runs.
    Recording,
    /// Send emails with Resend.
    #[cfg(feature = "email-resend")]
    Resend,
}

impl EmailDeliveryMode {
    /// Parses an email delivery mode.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the mode is unknown or unavailable for the
    /// enabled feature set.
    pub fn parse(value: &str) -> Result<Self, MailError> {
        match value {
            "recording" => Ok(Self::Recording),
            #[cfg(feature = "email-resend")]
            "resend" => Ok(Self::Resend),
            #[cfg(not(feature = "email-resend"))]
            "resend" => Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "resend_feature_disabled",
            )),
            _ => Err(MailError::with_detail(
                MailErrorCode::InvalidConfig,
                "email_mode",
            )),
        }
    }
}

/// Auth mailer selected from Harbor environment configuration.
#[derive(Clone)]
#[non_exhaustive]
pub enum ConfiguredAuthMailer {
    /// In-memory recording mailer.
    Recording(RecordingMailer),
    /// Resend-backed mailer.
    #[cfg(feature = "email-resend")]
    Resend(ResendMailer),
}

impl ConfiguredAuthMailer {
    /// Creates a configured auth mailer from `HARBOR_EMAIL_MODE`.
    ///
    /// `recording` uses Harbor's in-memory mailer. `resend` reads Resend
    /// configuration from `RESEND_API_KEY` and `HARBOR_EMAIL_FROM`.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the mode or provider configuration is
    /// missing or invalid.
    pub fn from_env() -> Result<Self, MailError> {
        let mode = std::env::var("HARBOR_EMAIL_MODE")
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "mode"))?;
        Self::from_mode(EmailDeliveryMode::parse(&mode)?)
    }

    /// Creates a configured auth mailer from a delivery mode.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the selected provider configuration is
    /// invalid.
    pub fn from_mode(mode: EmailDeliveryMode) -> Result<Self, MailError> {
        match mode {
            EmailDeliveryMode::Recording => Ok(Self::Recording(RecordingMailer::new())),
            #[cfg(feature = "email-resend")]
            EmailDeliveryMode::Resend => Ok(Self::Resend(ResendMailer::from_env()?)),
        }
    }
}

impl std::fmt::Debug for ConfiguredAuthMailer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match self {
            Self::Recording(_mailer) => "recording",
            #[cfg(feature = "email-resend")]
            Self::Resend(_mailer) => "resend",
        };
        formatter
            .debug_struct("ConfiguredAuthMailer")
            .field("mode", &mode)
            .finish_non_exhaustive()
    }
}

impl AuthMailer for ConfiguredAuthMailer {
    async fn send_auth_email(&self, email: AuthEmail) -> Result<MailDelivery, MailError> {
        match self {
            Self::Recording(mailer) => mailer.send_auth_email(email).await,
            #[cfg(feature = "email-resend")]
            Self::Resend(mailer) => mailer.send_auth_email(email).await,
        }
    }
}
