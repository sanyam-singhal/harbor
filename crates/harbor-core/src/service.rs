//! Core authentication services.

use crate::{
    Argon2PasswordHasher, AuthError, AuthErrorCode, AuthStore, ChallengeDelivery, ChallengePurpose,
    ChallengeRecord, Clock, CommonPasswordBlocklist, CreateChallengeInput, CreateSessionInput,
    CreateUserEmailInput, CreateUserInput, EmailAddress, FindEmailByCanonicalInput,
    GetChallengeInput, GetPasswordCredentialInput, GetSessionInput, HmacSecretKey,
    InsertPasswordInput, MarkEmailVerifiedInput, PasswordBlocklist, RedirectPath, RetryBudget,
    RevokeSessionInput, SecretGenerator, SecretHashPurpose, SecretToken, SessionRecord,
    UserEmailRecord, constant_time_token_hash_eq, hash_secret_token, new_challenge_id,
    new_session_id, new_user_email_id, new_user_id, random_otp_code, random_session_token,
    random_url_token,
};

const DEFAULT_IDLE_SESSION_MICROS: i64 = 12 * 60 * 60 * 1_000_000;
const DEFAULT_ABSOLUTE_SESSION_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;
const SIGNUP_CONFIRMATION_MICROS: i64 = 30 * 60 * 1_000_000;
const EMAIL_SIGNIN_MICROS: i64 = 10 * 60 * 1_000_000;
const PASSWORD_RESET_MICROS: i64 = 15 * 60 * 1_000_000;
const RESEND_COOLDOWN_MICROS: i64 = 60 * 1_000_000;

/// Core auth service.
#[derive(Clone)]
pub struct AuthService<S, C, G, B = CommonPasswordBlocklist> {
    store: S,
    clock: C,
    generator: G,
    hmac_key: HmacSecretKey,
    password_hasher: Argon2PasswordHasher,
    password_blocklist: B,
}

impl<S, C, G> AuthService<S, C, G, CommonPasswordBlocklist> {
    /// Creates an auth service with the default password blocklist.
    #[must_use]
    pub fn new(
        store: S,
        clock: C,
        generator: G,
        hmac_key: HmacSecretKey,
        password_hasher: Argon2PasswordHasher,
    ) -> Self {
        Self::with_blocklist(
            store,
            clock,
            generator,
            hmac_key,
            password_hasher,
            CommonPasswordBlocklist,
        )
    }
}

impl<S, C, G, B> AuthService<S, C, G, B> {
    /// Creates an auth service with an explicit password blocklist.
    #[must_use]
    pub fn with_blocklist(
        store: S,
        clock: C,
        generator: G,
        hmac_key: HmacSecretKey,
        password_hasher: Argon2PasswordHasher,
        password_blocklist: B,
    ) -> Self {
        Self {
            store,
            clock,
            generator,
            hmac_key,
            password_hasher,
            password_blocklist,
        }
    }
}

impl<S, C, G, B> AuthService<S, C, G, B>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    /// Creates an unverified user with a password credential.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when validation, hashing, randomness, or storage
    /// fails.
    pub async fn sign_up_with_password(
        &self,
        input: PasswordSignUpInput,
    ) -> Result<PasswordSignUpOutput, AuthError> {
        let email = EmailAddress::parse(input.email)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        let now = self.clock.now();
        let user_id = new_user_id(&self.generator)
            .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "user_id"))?;
        let email_id = new_user_email_id(&self.generator)
            .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "email_id"))?;
        let password_hash = self
            .password_hasher
            .hash_password(&input.password, &self.password_blocklist, &self.generator)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;

        let user = self
            .store
            .create_user(CreateUserInput {
                id: user_id.clone(),
                now,
            })
            .await
            .map_err(AuthError::from)?;
        let email_record = self
            .store
            .create_user_email(CreateUserEmailInput {
                id: email_id,
                user_id: user_id.clone(),
                email_original: email.original().to_owned(),
                email_canonical: email.canonical().clone(),
                is_primary: true,
                now,
            })
            .await
            .map_err(AuthError::from)?;
        self.store
            .upsert_password_credential(InsertPasswordInput {
                user_id,
                password_hash,
                password_set_at: now,
                password_version: 1,
            })
            .await
            .map_err(AuthError::from)?;

        Ok(PasswordSignUpOutput {
            user,
            email: email_record,
        })
    }

    /// Signs in with email and password, returning a new session token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when credentials are invalid, email is unverified,
    /// or session creation fails.
    pub async fn sign_in_with_password(
        &self,
        input: PasswordSignInInput,
    ) -> Result<PasswordSignInOutput, AuthError> {
        let email = EmailAddress::parse(input.email)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        let email_record = self
            .store
            .find_email_by_canonical(FindEmailByCanonicalInput {
                email_canonical: email.canonical().clone(),
            })
            .await
            .map_err(AuthError::from)?
            .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        if email_record.verified_at.is_none() {
            return Err(AuthError::new(AuthErrorCode::EmailNotVerified));
        }
        let credential = self
            .store
            .get_password_credential(GetPasswordCredentialInput {
                user_id: email_record.user_id.clone(),
            })
            .await
            .map_err(AuthError::from)?
            .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        let verification = self
            .password_hasher
            .verify_password(&input.password, &credential.password_hash)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        if !verification.verified {
            return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
        }

        let session_token = random_session_token(&self.generator)
            .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "session_token"))?;
        let token_hash = hash_secret_token(
            &self.hmac_key,
            SecretHashPurpose::SessionToken,
            &session_token,
        )
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "token_hash"))?;
        let now = self.clock.now();
        let session = self
            .store
            .create_session(CreateSessionInput {
                id: new_session_id(&self.generator).map_err(|_error| {
                    AuthError::with_detail(AuthErrorCode::Internal, "session_id")
                })?,
                user_id: email_record.user_id,
                token_hash,
                created_at: now,
                idle_expires_at: now
                    .checked_add_micros(DEFAULT_IDLE_SESSION_MICROS)
                    .ok_or_else(|| {
                        AuthError::with_detail(AuthErrorCode::Internal, "idle_expiry")
                    })?,
                absolute_expires_at: now
                    .checked_add_micros(DEFAULT_ABSOLUTE_SESSION_MICROS)
                    .ok_or_else(|| {
                        AuthError::with_detail(AuthErrorCode::Internal, "absolute_expiry")
                    })?,
                ip_hash: None,
                user_agent_hash: None,
            })
            .await
            .map_err(AuthError::from)?;

        Ok(PasswordSignInOutput {
            session,
            session_token,
            redirect_path: input.redirect_path,
        })
    }

    /// Loads the current session from a presented session token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when hashing or storage fails.
    pub async fn current_session(
        &self,
        session_token: &SecretToken,
    ) -> Result<Option<CurrentSession>, AuthError> {
        let token_hash = hash_secret_token(
            &self.hmac_key,
            SecretHashPurpose::SessionToken,
            session_token,
        )
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "token_hash"))?;
        let session = self
            .store
            .get_session_by_token_hash(GetSessionInput { token_hash })
            .await
            .map_err(AuthError::from)?;
        let Some(session) = session else {
            return Ok(None);
        };
        let now = self.clock.now();
        if session.revoked_at.is_some()
            || session.idle_expires_at <= now
            || session.absolute_expires_at <= now
        {
            return Ok(None);
        }
        Ok(Some(CurrentSession { session }))
    }

    /// Revokes the session identified by a presented session token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when hashing or storage fails.
    pub async fn sign_out(&self, session_token: &SecretToken) -> Result<bool, AuthError> {
        let Some(current) = self.current_session(session_token).await? else {
            return Ok(false);
        };
        let revoked = self
            .store
            .revoke_session(RevokeSessionInput {
                session_id: current.session.id,
                revoked_at: self.clock.now(),
            })
            .await
            .map_err(AuthError::from)?;
        Ok(revoked.is_some())
    }

    /// Creates an email challenge and returns the secret that should be sent.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when input validation, randomness, hashing, or
    /// storage fails.
    pub async fn create_email_challenge(
        &self,
        input: EmailChallengeInput,
    ) -> Result<EmailChallengeOutput, AuthError> {
        let email = EmailAddress::parse(input.email)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        let secret = match input.delivery {
            ChallengeDelivery::OtpCode => random_otp_code(&self.generator),
            ChallengeDelivery::MagicLink | ChallengeDelivery::Both => {
                random_url_token(&self.generator)
            }
        }
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "challenge_secret"))?;
        let secret_hash = hash_secret_token(
            &self.hmac_key,
            secret_hash_purpose_for_delivery(input.delivery),
            &secret,
        )
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "challenge_hash"))?;
        let now = self.clock.now();
        let expires_at = now
            .checked_add_micros(challenge_lifetime(input.purpose))
            .ok_or_else(|| AuthError::with_detail(AuthErrorCode::Internal, "challenge_expiry"))?;
        let resend_after = now
            .checked_add_micros(RESEND_COOLDOWN_MICROS)
            .ok_or_else(|| AuthError::with_detail(AuthErrorCode::Internal, "resend_after"))?;
        let challenge = self
            .store
            .create_challenge(CreateChallengeInput {
                id: new_challenge_id(&self.generator).map_err(|_error| {
                    AuthError::with_detail(AuthErrorCode::Internal, "challenge_id")
                })?,
                purpose: input.purpose,
                user_id: input.user_id,
                email_canonical: email.canonical().clone(),
                secret_hash,
                delivery: input.delivery,
                redirect_path: input.redirect_path,
                expires_at,
                max_attempts: RetryBudget::try_new(5).map_err(|_error| {
                    AuthError::with_detail(AuthErrorCode::Internal, "attempts")
                })?,
                resend_after,
                now,
            })
            .await
            .map_err(AuthError::from)?;

        Ok(EmailChallengeOutput { challenge, secret })
    }

    /// Verifies and consumes an email challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the challenge is missing, expired, exhausted,
    /// already consumed, or the secret does not match.
    pub async fn verify_email_challenge(
        &self,
        input: VerifyChallengeInput,
    ) -> Result<VerifiedChallenge, AuthError> {
        let challenge = self
            .store
            .get_challenge(GetChallengeInput {
                challenge_id: input.challenge_id.clone(),
            })
            .await
            .map_err(AuthError::from)?
            .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        if challenge.purpose != input.purpose || challenge.consumed_at.is_some() {
            return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
        }
        let now = self.clock.now();
        if challenge.expires_at <= now {
            return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
        }
        let attempt_count = usize::try_from(challenge.attempt_count).unwrap_or(usize::MAX);
        if attempt_count >= challenge.max_attempts.get() {
            return Err(AuthError::new(AuthErrorCode::RateLimited));
        }
        let presented_hash = hash_secret_token(
            &self.hmac_key,
            secret_hash_purpose_for_delivery(challenge.delivery),
            &input.secret,
        )
        .map_err(|_error| AuthError::with_detail(AuthErrorCode::Internal, "challenge_hash"))?;
        if !constant_time_token_hash_eq(&presented_hash, &challenge.secret_hash) {
            self.store
                .increment_challenge_attempts(crate::IncrementChallengeAttemptsInput {
                    challenge_id: input.challenge_id,
                })
                .await
                .map_err(AuthError::from)?;
            return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
        }

        let consumed = self
            .store
            .consume_challenge(
                GetChallengeInput {
                    challenge_id: input.challenge_id,
                },
                now,
            )
            .await
            .map_err(AuthError::from)?
            .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        if consumed.purpose == ChallengePurpose::SignupConfirmation {
            self.store
                .mark_email_verified(MarkEmailVerifiedInput {
                    email_canonical: consumed.email_canonical.clone(),
                    verified_at: now,
                })
                .await
                .map_err(AuthError::from)?;
        }

        Ok(VerifiedChallenge {
            challenge: consumed,
        })
    }
}

fn challenge_lifetime(purpose: ChallengePurpose) -> i64 {
    match purpose {
        ChallengePurpose::SignupConfirmation => SIGNUP_CONFIRMATION_MICROS,
        ChallengePurpose::EmailSignIn => EMAIL_SIGNIN_MICROS,
        ChallengePurpose::PasswordReset => PASSWORD_RESET_MICROS,
    }
}

fn secret_hash_purpose_for_delivery(delivery: ChallengeDelivery) -> SecretHashPurpose {
    match delivery {
        ChallengeDelivery::OtpCode => SecretHashPurpose::OtpCode,
        ChallengeDelivery::MagicLink | ChallengeDelivery::Both => SecretHashPurpose::UrlToken,
    }
}

/// Password signup input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSignUpInput {
    /// User email.
    pub email: String,
    /// User password.
    pub password: String,
}

/// Password signup output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSignUpOutput {
    /// Created user.
    pub user: crate::UserRecord,
    /// Created unverified email.
    pub email: UserEmailRecord,
}

/// Password signin input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSignInInput {
    /// User email.
    pub email: String,
    /// User password.
    pub password: String,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Password signin output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSignInOutput {
    /// Created session.
    pub session: SessionRecord,
    /// Raw session token to set in an HttpOnly cookie.
    pub session_token: SecretToken,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Current session view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentSession {
    /// Active session.
    pub session: SessionRecord,
}

/// Email challenge creation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailChallengeInput {
    /// Challenge purpose.
    pub purpose: ChallengePurpose,
    /// Delivery style.
    pub delivery: ChallengeDelivery,
    /// Target email.
    pub email: String,
    /// Optional linked user.
    pub user_id: Option<crate::UserId>,
    /// Optional post-verification redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Created email challenge and secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailChallengeOutput {
    /// Persisted challenge.
    pub challenge: ChallengeRecord,
    /// Secret to deliver by email.
    pub secret: SecretToken,
}

/// Email challenge verification input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyChallengeInput {
    /// Challenge id.
    pub challenge_id: crate::ChallengeId,
    /// Expected purpose.
    pub purpose: ChallengePurpose,
    /// Presented secret.
    pub secret: SecretToken,
}

/// Verified email challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChallenge {
    /// Consumed challenge.
    pub challenge: ChallengeRecord,
}
