//! Flow-level auth configuration for Harbor Leptos integrations.

use harbor_core::PasswordlessSignup;

/// Configuration for Harbor's v0.1 auth flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFlowConfig {
    email_and_password: EmailAndPasswordConfig,
    magic_link: PasswordlessEmailFlowConfig,
    email_otp: PasswordlessEmailFlowConfig,
    password_reset: PasswordResetConfig,
}

impl AuthFlowConfig {
    /// Returns email/password flow config.
    #[must_use]
    pub const fn email_and_password(&self) -> &EmailAndPasswordConfig {
        &self.email_and_password
    }

    /// Returns magic-link flow config.
    #[must_use]
    pub const fn magic_link(&self) -> &PasswordlessEmailFlowConfig {
        &self.magic_link
    }

    /// Returns email OTP flow config.
    #[must_use]
    pub const fn email_otp(&self) -> &PasswordlessEmailFlowConfig {
        &self.email_otp
    }

    /// Returns password-reset flow config.
    #[must_use]
    pub const fn password_reset(&self) -> &PasswordResetConfig {
        &self.password_reset
    }

    /// Updates email/password flow config.
    #[must_use]
    pub fn with_email_and_password(mut self, value: EmailAndPasswordConfig) -> Self {
        self.email_and_password = value;
        self
    }

    /// Updates magic-link flow config.
    #[must_use]
    pub fn with_magic_link(mut self, value: PasswordlessEmailFlowConfig) -> Self {
        self.magic_link = value;
        self
    }

    /// Updates email OTP flow config.
    #[must_use]
    pub fn with_email_otp(mut self, value: PasswordlessEmailFlowConfig) -> Self {
        self.email_otp = value;
        self
    }

    /// Updates password-reset flow config.
    #[must_use]
    pub fn with_password_reset(mut self, value: PasswordResetConfig) -> Self {
        self.password_reset = value;
        self
    }
}

impl Default for AuthFlowConfig {
    fn default() -> Self {
        Self {
            email_and_password: EmailAndPasswordConfig::default(),
            magic_link: PasswordlessEmailFlowConfig::default(),
            email_otp: PasswordlessEmailFlowConfig::default(),
            password_reset: PasswordResetConfig::default(),
        }
    }
}

/// Email/password auth flow configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailAndPasswordConfig {
    enabled: bool,
    require_email_confirmation: bool,
}

impl EmailAndPasswordConfig {
    /// Creates email/password flow config.
    #[must_use]
    pub const fn new(enabled: bool, require_email_confirmation: bool) -> Self {
        Self {
            enabled,
            require_email_confirmation,
        }
    }

    /// Enables the flow.
    #[must_use]
    pub const fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disables the flow.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Sets whether password sign-in requires confirmed email.
    #[must_use]
    pub const fn require_email_confirmation(mut self, value: bool) -> Self {
        self.require_email_confirmation = value;
        self
    }

    /// Returns whether the flow is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Returns whether password sign-in requires confirmed email.
    #[must_use]
    pub const fn requires_email_confirmation(self) -> bool {
        self.require_email_confirmation
    }
}

impl Default for EmailAndPasswordConfig {
    fn default() -> Self {
        Self::new(true, true)
    }
}

/// Passwordless email flow configuration for magic link and OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordlessEmailFlowConfig {
    enabled: bool,
    passwordless_signup: PasswordlessSignup,
}

impl PasswordlessEmailFlowConfig {
    /// Creates passwordless email flow config.
    #[must_use]
    pub const fn new(enabled: bool, passwordless_signup: PasswordlessSignup) -> Self {
        Self {
            enabled,
            passwordless_signup,
        }
    }

    /// Enables the flow.
    #[must_use]
    pub const fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disables the flow.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Allows creating verified passwordless accounts from this flow.
    #[must_use]
    pub const fn create_users(mut self, value: bool) -> Self {
        self.passwordless_signup = if value {
            PasswordlessSignup::Allowed
        } else {
            PasswordlessSignup::Disabled
        };
        self
    }

    /// Sets the passwordless signup policy.
    #[must_use]
    pub const fn with_passwordless_signup(mut self, value: PasswordlessSignup) -> Self {
        self.passwordless_signup = value;
        self
    }

    /// Returns whether the flow is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Returns the passwordless signup policy.
    #[must_use]
    pub const fn passwordless_signup(self) -> PasswordlessSignup {
        self.passwordless_signup
    }
}

impl Default for PasswordlessEmailFlowConfig {
    fn default() -> Self {
        Self::new(true, PasswordlessSignup::Allowed)
    }
}

/// Password reset auth flow configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordResetConfig {
    enabled: bool,
}

impl PasswordResetConfig {
    /// Creates password reset flow config.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Enables the flow.
    #[must_use]
    pub const fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disables the flow.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Returns whether the flow is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self::new(true)
    }
}
