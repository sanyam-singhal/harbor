//! Validated test data factories.

use harbor_core::{
    AuthEventId, ChallengeId, DomainError, EmailAddress, SessionId, TokenHash, UserEmailId, UserId,
};

/// Deterministic source of unique Harbor domain values for tests.
#[derive(Debug, Clone)]
pub struct TestIdFactory {
    namespace: String,
    next: u64,
}

impl TestIdFactory {
    /// Creates a factory with a stable namespace.
    #[must_use]
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_start(namespace, 1)
    }

    /// Creates a factory with a stable namespace and starting counter.
    #[must_use]
    pub fn with_start(namespace: impl Into<String>, start: u64) -> Self {
        Self {
            namespace: namespace.into(),
            next: start.max(1),
        }
    }

    /// Creates a valid user id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// domain contract.
    pub fn user_id(&mut self) -> Result<UserId, DomainError> {
        UserId::try_new(format!("user{:012}", self.take()))
    }

    /// Creates a valid user-email row id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// domain contract.
    pub fn user_email_id(&mut self) -> Result<UserEmailId, DomainError> {
        UserEmailId::try_new(format!("email{:011}", self.take()))
    }

    /// Creates a valid challenge id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// domain contract.
    pub fn challenge_id(&mut self) -> Result<ChallengeId, DomainError> {
        ChallengeId::try_new(format!("challenge{:07}", self.take()))
    }

    /// Creates a valid session id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// domain contract.
    pub fn session_id(&mut self) -> Result<SessionId, DomainError> {
        SessionId::try_new(format!("session{:09}", self.take()))
    }

    /// Creates a valid auth event id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// domain contract.
    pub fn auth_event_id(&mut self) -> Result<AuthEventId, DomainError> {
        AuthEventId::try_new(format!("event{:011}", self.take()))
    }

    /// Creates a unique accepted email address.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// email contract.
    pub fn email(&mut self) -> Result<EmailAddress, DomainError> {
        let label = safe_email_label(&self.namespace);
        EmailAddress::parse(format!("{label}.{:012}@example.test", self.take()))
    }

    /// Creates a stable request fingerprint string.
    #[must_use]
    pub fn request_fingerprint(&mut self) -> String {
        let value = self.take();
        format!("client=203.0.113.{};ua=harbor-test-{value}", value % 255)
    }

    /// Creates a valid token hash.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the generated fixture value violates the
    /// token-hash contract.
    pub fn token_hash(&mut self) -> Result<TokenHash, DomainError> {
        let seed = self.take().to_le_bytes();
        let mut bytes = Vec::with_capacity(32);
        while bytes.len() < 32 {
            bytes.extend_from_slice(&seed);
        }
        bytes.truncate(32);
        TokenHash::try_new(bytes)
    }

    fn take(&mut self) -> u64 {
        let value = self.next;
        self.next = self.next.saturating_add(1);
        value
    }
}

impl Default for TestIdFactory {
    fn default() -> Self {
        Self::new("test")
    }
}

fn safe_email_label(value: &str) -> String {
    let mut label = String::new();
    for character in value.chars().take(24) {
        if character.is_ascii_alphanumeric() {
            label.push(character.to_ascii_lowercase());
        } else if character == '-' || character == '_' {
            label.push('.');
        }
    }
    if label.is_empty() {
        label.push_str("test");
    }
    label
}
