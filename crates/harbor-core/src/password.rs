//! Password policy and Argon2id password hashing.

use core::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::ports::{RandomError, SecretGenerator};

const DEFAULT_MIN_PASSWORD_CHARS: usize = 15;
const DEFAULT_MAX_PASSWORD_BYTES: usize = 1024;
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 19_456;
const DEFAULT_ARGON2_ITERATIONS: u32 = 2;
const DEFAULT_ARGON2_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;

/// Password validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordError {
    /// The password is shorter than the configured minimum.
    TooShort,
    /// The password is longer than the configured maximum byte length.
    TooLong,
    /// The password is present in the configured blocklist.
    Blocklisted,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooShort => "password is too short",
            Self::TooLong => "password is too long",
            Self::Blocklisted => "password is blocklisted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PasswordError {}

/// Password hashing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordHashError {
    /// Password validation failed.
    Password(PasswordError),
    /// Random salt generation failed.
    Random(RandomError),
    /// Argon2 parameter construction failed.
    InvalidParameters,
    /// PHC string hashing failed.
    HashFailed,
    /// Stored PHC string could not be parsed.
    InvalidStoredHash,
}

impl fmt::Display for PasswordHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(error) => write!(formatter, "{error}"),
            Self::Random(error) => write!(formatter, "random generation failed: {error}"),
            Self::InvalidParameters => formatter.write_str("invalid Argon2 parameters"),
            Self::HashFailed => formatter.write_str("password hashing failed"),
            Self::InvalidStoredHash => formatter.write_str("stored password hash is invalid"),
        }
    }
}

impl std::error::Error for PasswordHashError {}

impl From<PasswordError> for PasswordHashError {
    fn from(value: PasswordError) -> Self {
        Self::Password(value)
    }
}

impl From<RandomError> for PasswordHashError {
    fn from(value: RandomError) -> Self {
        Self::Random(value)
    }
}

/// Password blocklist abstraction.
pub trait PasswordBlocklist: Clone + Send + Sync + 'static {
    /// Returns true when `password` is too common or compromised to accept.
    fn contains(&self, password: &str) -> bool;
}

/// Tiny built-in password blocklist.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommonPasswordBlocklist;

impl PasswordBlocklist for CommonPasswordBlocklist {
    fn contains(&self, password: &str) -> bool {
        const BLOCKED: &[&str] = &[
            "passwordpassword",
            "passwordpasswordpassword",
            "123456789012345",
            "qwertyqwertyqwerty",
            "letmeinletmeinletmein",
        ];

        let lowercase = password.to_ascii_lowercase();
        BLOCKED.contains(&lowercase.as_str())
    }
}

/// Password acceptance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    min_chars: usize,
    max_bytes: usize,
}

impl PasswordPolicy {
    /// Creates a password policy.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError`] when the bounds are internally invalid.
    pub const fn try_new(min_chars: usize, max_bytes: usize) -> Result<Self, PasswordError> {
        if min_chars == 0 {
            return Err(PasswordError::TooShort);
        }
        if max_bytes < min_chars {
            return Err(PasswordError::TooLong);
        }
        Ok(Self {
            min_chars,
            max_bytes,
        })
    }

    /// Returns the default v0.1 password policy.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            min_chars: DEFAULT_MIN_PASSWORD_CHARS,
            max_bytes: DEFAULT_MAX_PASSWORD_BYTES,
        }
    }

    /// Minimum accepted password length in Unicode scalar values.
    #[must_use]
    pub const fn min_chars(self) -> usize {
        self.min_chars
    }

    /// Maximum accepted password size in UTF-8 bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Validates a password.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError`] when the password is too short, too long, or
    /// blocked by the supplied blocklist.
    pub fn validate(
        self,
        password: &str,
        blocklist: &impl PasswordBlocklist,
    ) -> Result<(), PasswordError> {
        if password.chars().count() < self.min_chars {
            return Err(PasswordError::TooShort);
        }
        if password.len() > self.max_bytes {
            return Err(PasswordError::TooLong);
        }
        if blocklist.contains(password) {
            return Err(PasswordError::Blocklisted);
        }
        Ok(())
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Argon2id parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    memory_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Params {
    /// Creates Argon2id parameters.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordHashError::InvalidParameters`] when the Argon2 crate
    /// rejects the supplied values.
    pub fn try_new(
        memory_cost_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, PasswordHashError> {
        Params::new(memory_cost_kib, iterations, parallelism, None)
            .map_err(|_error| PasswordHashError::InvalidParameters)?;
        Ok(Self {
            memory_cost_kib,
            iterations,
            parallelism,
        })
    }

    /// Returns OWASP's v0.1 Harbor default: Argon2id m=19456 KiB, t=2, p=1.
    #[must_use]
    pub const fn owasp_minimum() -> Self {
        Self {
            memory_cost_kib: DEFAULT_ARGON2_MEMORY_KIB,
            iterations: DEFAULT_ARGON2_ITERATIONS,
            parallelism: DEFAULT_ARGON2_PARALLELISM,
        }
    }

    /// Memory cost in KiB.
    #[must_use]
    pub const fn memory_cost_kib(self) -> u32 {
        self.memory_cost_kib
    }

    /// Iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism.
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    fn into_argon2_params(self) -> Result<Params, PasswordHashError> {
        Params::new(
            self.memory_cost_kib,
            self.iterations,
            self.parallelism,
            None,
        )
        .map_err(|_error| PasswordHashError::InvalidParameters)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::owasp_minimum()
    }
}

/// Stored PHC password hash string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PasswordHashString(String);

impl PasswordHashString {
    /// Creates a stored hash wrapper after basic PHC shape validation.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordHashError::InvalidStoredHash`] when the PHC string
    /// cannot be parsed.
    pub fn try_new(value: impl Into<String>) -> Result<Self, PasswordHashError> {
        let value = value.into();
        PasswordHash::new(&value).map_err(|_error| PasswordHashError::InvalidStoredHash)?;
        Ok(Self(value))
    }

    /// Exposes the PHC string for persistence or verification.
    #[must_use]
    pub fn expose_phc(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHashString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashString([REDACTED])")
    }
}

/// Result of checking a password against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordVerification {
    /// Whether the password matched the stored hash.
    pub verified: bool,
    /// Whether the stored hash should be upgraded after successful verification.
    pub needs_rehash: bool,
}

/// Argon2id password hasher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2PasswordHasher {
    params: Argon2Params,
    policy: PasswordPolicy,
}

impl Argon2PasswordHasher {
    /// Creates a password hasher from explicit policy and parameters.
    #[must_use]
    pub const fn new(policy: PasswordPolicy, params: Argon2Params) -> Self {
        Self { params, policy }
    }

    /// Returns the configured password policy.
    #[must_use]
    pub const fn policy(self) -> PasswordPolicy {
        self.policy
    }

    /// Returns the configured Argon2id parameters.
    #[must_use]
    pub const fn params(self) -> Argon2Params {
        self.params
    }

    /// Hashes a password to a PHC string.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordHashError`] when password validation, salt generation,
    /// parameter validation, or hashing fails.
    pub fn hash_password(
        self,
        password: &str,
        blocklist: &impl PasswordBlocklist,
        generator: &impl SecretGenerator,
    ) -> Result<PasswordHashString, PasswordHashError> {
        self.policy.validate(password, blocklist)?;
        let salt = generate_salt(generator)?;
        let argon2 = self.argon2()?;
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_error| PasswordHashError::HashFailed)?;

        PasswordHashString::try_new(hash.to_string())
    }

    /// Verifies a password against a stored PHC string.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordHashError::InvalidStoredHash`] when the stored PHC
    /// string cannot be parsed.
    pub fn verify_password(
        self,
        password: &str,
        stored_hash: &PasswordHashString,
    ) -> Result<PasswordVerification, PasswordHashError> {
        let parsed = PasswordHash::new(stored_hash.expose_phc())
            .map_err(|_error| PasswordHashError::InvalidStoredHash)?;
        let argon2 = self.argon2()?;
        let verified = argon2.verify_password(password.as_bytes(), &parsed).is_ok();
        Ok(PasswordVerification {
            verified,
            needs_rehash: verified && self.needs_rehash(stored_hash),
        })
    }

    fn argon2(self) -> Result<Argon2<'static>, PasswordHashError> {
        Ok(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            self.params.into_argon2_params()?,
        ))
    }

    fn needs_rehash(self, stored_hash: &PasswordHashString) -> bool {
        let expected = format!(
            "m={},t={},p={}",
            self.params.memory_cost_kib, self.params.iterations, self.params.parallelism
        );
        !stored_hash.expose_phc().contains(&expected)
    }
}

impl Default for Argon2PasswordHasher {
    fn default() -> Self {
        Self::new(PasswordPolicy::default(), Argon2Params::default())
    }
}

fn generate_salt(generator: &impl SecretGenerator) -> Result<SaltString, PasswordHashError> {
    let mut bytes = [0_u8; SALT_BYTES];
    generator.fill_bytes(&mut bytes)?;
    SaltString::encode_b64(&bytes).map_err(|_error| PasswordHashError::HashFailed)
}

#[cfg(test)]
mod tests {
    use super::{
        Argon2Params, Argon2PasswordHasher, CommonPasswordBlocklist, PasswordError,
        PasswordHashString, PasswordPolicy,
    };
    use crate::ports::{RandomError, SecretGenerator};

    #[derive(Clone)]
    struct FixedGenerator;

    impl SecretGenerator for FixedGenerator {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            for (index, byte) in dest.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        }
    }

    fn fast_hasher() -> Result<Argon2PasswordHasher, super::PasswordHashError> {
        Ok(Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ))
    }

    #[test]
    fn default_policy_matches_v0_1_security_decision() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_chars(), 15);
        assert_eq!(policy.max_bytes(), 1024);

        let params = Argon2Params::default();
        assert_eq!(params.memory_cost_kib(), 19_456);
        assert_eq!(params.iterations(), 2);
        assert_eq!(params.parallelism(), 1);
    }

    #[test]
    fn password_policy_rejects_short_long_and_blocklisted_values() {
        let policy = PasswordPolicy::try_new(15, 32);
        assert!(policy.is_ok());
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => return assert_eq!(error, PasswordError::TooShort),
        };
        let blocklist = CommonPasswordBlocklist;

        assert_eq!(
            policy.validate("short", &blocklist),
            Err(PasswordError::TooShort)
        );
        assert_eq!(
            policy.validate("123456789012345678901234567890123", &blocklist),
            Err(PasswordError::TooLong)
        );
        assert_eq!(
            policy.validate("passwordpassword", &blocklist),
            Err(PasswordError::Blocklisted)
        );
        assert!(
            policy
                .validate("correct horse battery staple", &blocklist)
                .is_ok()
        );
        assert_eq!(PasswordPolicy::try_new(0, 32), Err(PasswordError::TooShort));
        assert_eq!(PasswordPolicy::try_new(15, 14), Err(PasswordError::TooLong));
        assert_eq!(PasswordError::TooShort.to_string(), "password is too short");
        assert_eq!(PasswordError::TooLong.to_string(), "password is too long");
        assert_eq!(
            PasswordError::Blocklisted.to_string(),
            "password is blocklisted"
        );
    }

    #[test]
    fn password_hash_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let hasher = fast_hasher()?;
        let generator = FixedGenerator;
        let hash = hasher.hash_password(
            "correct horse battery staple",
            &CommonPasswordBlocklist,
            &generator,
        )?;

        assert_eq!(format!("{hash:?}"), "PasswordHashString([REDACTED])");
        assert!(hash.expose_phc().starts_with("$argon2id$"));
        Ok(())
    }

    #[test]
    fn password_hash_verifies_and_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>>
    {
        let hasher = fast_hasher()?;
        let generator = FixedGenerator;
        let hash = hasher.hash_password(
            "correct horse battery staple",
            &CommonPasswordBlocklist,
            &generator,
        )?;

        let verified = hasher.verify_password("correct horse battery staple", &hash)?;
        let rejected = hasher.verify_password("wrong horse battery staple", &hash)?;

        assert!(verified.verified);
        assert!(!verified.needs_rehash);
        assert!(!rejected.verified);
        Ok(())
    }

    #[test]
    fn verification_flags_rehash_for_old_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let old_hasher = Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        );
        let new_hasher = Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(64, 1, 1)?,
        );
        let generator = FixedGenerator;
        let hash = old_hasher.hash_password(
            "correct horse battery staple",
            &CommonPasswordBlocklist,
            &generator,
        )?;

        let verified = new_hasher.verify_password("correct horse battery staple", &hash)?;

        assert!(verified.verified);
        assert!(verified.needs_rehash);
        Ok(())
    }

    #[test]
    fn invalid_stored_hash_is_rejected() {
        assert!(PasswordHashString::try_new("not-a-phc-string").is_err());
    }

    #[test]
    fn random_error_converts_to_hash_error_without_leaking_secret_context() {
        let error = super::PasswordHashError::from(RandomError::SystemRandom);
        assert_eq!(
            error.to_string(),
            "random generation failed: system random source failed"
        );
        assert_eq!(
            super::PasswordHashError::from(PasswordError::TooShort).to_string(),
            "password is too short"
        );
        assert_eq!(
            super::PasswordHashError::InvalidParameters.to_string(),
            "invalid Argon2 parameters"
        );
        assert_eq!(
            super::PasswordHashError::HashFailed.to_string(),
            "password hashing failed"
        );
        assert_eq!(
            super::PasswordHashError::InvalidStoredHash.to_string(),
            "stored password hash is invalid"
        );
    }
}
