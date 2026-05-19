use core::fmt;

use harbor_core::{CanonicalEmail, EmailAddress, MailError, MailErrorCode};

/// Recipient accepted by Harbor email delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailRecipient {
    original: String,
    canonical: CanonicalEmail,
}

impl EmailRecipient {
    /// Parses and canonicalizes an email recipient.
    ///
    /// # Errors
    ///
    /// Returns [`MailError`] when the address is not accepted by Harbor's
    /// conservative email parser.
    pub fn parse(value: impl Into<String>) -> Result<Self, MailError> {
        let email = EmailAddress::parse(value)
            .map_err(|_error| MailError::with_detail(MailErrorCode::InvalidConfig, "recipient"))?;
        let (original, canonical) = email.into_parts();
        Ok(Self {
            original,
            canonical,
        })
    }

    /// Returns the original accepted email spelling.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Returns the canonical lookup email.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalEmail {
        &self.canonical
    }
}

impl fmt::Debug for EmailRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailRecipient")
            .field("canonical", &self.canonical)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[test]
fn recipient_preserves_original_and_canonical_email() -> Result<(), Box<dyn std::error::Error>> {
    let recipient = EmailRecipient::parse("User@Example.com")?;

    assert_eq!(recipient.original(), "User@Example.com");
    assert_eq!(recipient.canonical().as_str(), "user@example.com");
    assert!(EmailRecipient::parse("not-an-email").is_err());
    Ok(())
}
