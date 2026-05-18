//! Core authentication services.

use crate::{
    Argon2PasswordHasher, AuthError, AuthErrorCode, AuthStore, Clock, CommonPasswordBlocklist,
    CreateSessionInput, CreateUserEmailInput, CreateUserInput, EmailAddress,
    FindEmailByCanonicalInput, GetPasswordCredentialInput, GetSessionInput, HmacSecretKey,
    InsertPasswordInput, PasswordBlocklist, RedirectPath, RevokeSessionInput, SecretGenerator,
    SecretHashPurpose, SecretToken, SessionRecord, UserEmailRecord, hash_secret_token,
    new_session_id, new_user_email_id, new_user_id, random_session_token,
};

const DEFAULT_IDLE_SESSION_MICROS: i64 = 12 * 60 * 60 * 1_000_000;
const DEFAULT_ABSOLUTE_SESSION_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;

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
