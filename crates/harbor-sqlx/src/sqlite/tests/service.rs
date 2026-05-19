use super::*;

#[tokio::test(flavor = "current_thread")]
async fn email_challenge_service_rejects_bad_secret_and_consumed_reuse()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );

    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::OtpCode,
            email: "challenge@example.com".to_owned(),
            user_id: None,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    assert_eq!(challenge.secret.expose_secret().len(), 8);
    assert!(
        challenge
            .secret
            .expose_secret()
            .chars()
            .all(|character| character.is_ascii_digit())
    );

    let bad_secret = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: challenge.challenge.id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            secret: SecretToken::try_new("00000000")?,
        })
        .await;
    let bad_secret = match bad_secret {
        Ok(_) => return Err("wrong challenge secret should fail".into()),
        Err(error) => error,
    };
    assert_eq!(bad_secret.code(), AuthErrorCode::InvalidCredentials);

    let incremented = store
        .get_challenge(GetChallengeInput {
            challenge_id: challenge.challenge.id.clone(),
        })
        .await?;
    let incremented = match incremented {
        Some(challenge) => challenge,
        None => return Err("challenge should remain after failed attempt".into()),
    };
    assert_eq!(incremented.attempt_count, 1);

    let verified = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: challenge.challenge.id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            secret: challenge.secret,
        })
        .await?;
    assert_eq!(
        verified.challenge.redirect_path,
        Some(RedirectPath::try_new("/account")?)
    );

    let reused = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: challenge.challenge.id,
            purpose: ChallengePurpose::EmailSignIn,
            secret: SecretToken::try_new("00000000")?,
        })
        .await;
    let reused = match reused {
        Ok(_) => return Err("consumed challenge should be single use".into()),
        Err(error) => error,
    };
    assert_eq!(reused.code(), AuthErrorCode::InvalidCredentials);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn service_negative_paths_are_enumeration_safe() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let hmac_key = HmacSecretKey::try_new(vec![9; 32])?;
    let service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        hmac_key.clone(),
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );

    let invalid_signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "not-an-email".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await;
    let invalid_signup = match invalid_signup {
        Ok(_) => return Err("invalid signup email should fail".into()),
        Err(error) => error,
    };
    assert_eq!(invalid_signup.code(), AuthErrorCode::InvalidCredentials);

    let short_password = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "short@example.com".to_owned(),
            password: "short".to_owned(),
        })
        .await;
    let short_password = match short_password {
        Ok(_) => return Err("short signup password should fail".into()),
        Err(error) => error,
    };
    assert_eq!(short_password.code(), AuthErrorCode::InvalidCredentials);

    let unknown_signin = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "missing@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let unknown_signin = match unknown_signin {
        Ok(_) => return Err("unknown signin should fail".into()),
        Err(error) => error,
    };
    assert_eq!(unknown_signin.code(), AuthErrorCode::InvalidCredentials);

    let missing_session = SecretToken::try_new("missing-session-token")?;
    assert_eq!(service.current_session(&missing_session).await?, None);
    assert!(!service.sign_out(&missing_session).await?);

    let bad_challenge_email = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "not-an-email".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await;
    let bad_challenge_email = match bad_challenge_email {
        Ok(_) => return Err("invalid challenge email should fail".into()),
        Err(error) => error,
    };
    assert_eq!(
        bad_challenge_email.code(),
        AuthErrorCode::InvalidCredentials
    );

    let unverified = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "unverified-reset@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let unverified_reset = service
        .request_password_reset(harbor_core::RequestPasswordResetInput {
            email: unverified.email.email_original,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
        })
        .await?;
    assert_eq!(unverified_reset.challenge, None);

    let expiring = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "expired@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await?;
    let late_service = AuthService::new(
        store.clone(),
        FixedClock::new(UnixTimestampMicros::try_new(11 * 60 * 1_000_000)?),
        DeterministicSecretGenerator::new(),
        hmac_key.clone(),
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let expired = late_service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: expiring.challenge.id,
            purpose: ChallengePurpose::EmailSignIn,
            secret: expiring.secret,
        })
        .await;
    let expired = match expired {
        Ok(_) => return Err("expired challenge should fail".into()),
        Err(error) => error,
    };
    assert_eq!(expired.code(), AuthErrorCode::InvalidCredentials);

    let secret = SecretToken::try_new("correct-secret")?;
    let rate_limited_id = ChallengeId::try_new("challenge00000099")?;
    store
        .create_challenge(CreateChallengeInput {
            id: rate_limited_id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            user_id: None,
            email_canonical: EmailAddress::parse("limited@example.com")?
                .canonical()
                .clone(),
            secret_hash: hash_secret_token(&hmac_key, SecretHashPurpose::UrlToken, &secret)?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
            expires_at: UnixTimestampMicros::try_new(60_000_000)?,
            max_attempts: RetryBudget::ONE,
            resend_after: now(),
            now: now(),
        })
        .await?;
    let wrong_secret = SecretToken::try_new("wrong-secret")?;
    let first_wrong = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: rate_limited_id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            secret: wrong_secret.clone(),
        })
        .await;
    assert!(first_wrong.is_err());
    let rate_limited = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: rate_limited_id,
            purpose: ChallengePurpose::EmailSignIn,
            secret: wrong_secret,
        })
        .await;
    let rate_limited = match rate_limited {
        Ok(_) => return Err("exhausted challenge should rate limit".into()),
        Err(error) => error,
    };
    assert_eq!(rate_limited.code(), AuthErrorCode::RateLimited);

    let reset_secret = SecretToken::try_new("reset-secret")?;
    let reset_id = ChallengeId::try_new("challenge00000100")?;
    store
        .create_challenge(CreateChallengeInput {
            id: reset_id.clone(),
            purpose: ChallengePurpose::PasswordReset,
            user_id: None,
            email_canonical: EmailAddress::parse("resetless@example.com")?
                .canonical()
                .clone(),
            secret_hash: hash_secret_token(&hmac_key, SecretHashPurpose::UrlToken, &reset_secret)?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
            expires_at: UnixTimestampMicros::try_new(60_000_000)?,
            max_attempts: RetryBudget::try_new(5)?,
            resend_after: now(),
            now: now(),
        })
        .await?;
    let no_user_reset = service
        .reset_password(harbor_core::ResetPasswordInput {
            challenge_id: reset_id,
            secret: reset_secret,
            new_password: "new correct horse battery staple".to_owned(),
        })
        .await;
    let no_user_reset = match no_user_reset {
        Ok(_) => return Err("password reset without user id should fail".into()),
        Err(error) => error,
    };
    assert_eq!(no_user_reset.code(), AuthErrorCode::InvalidCredentials);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn service_rejects_expiry_overflow_without_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let store = migrated_store().await?;
    let hmac_key = HmacSecretKey::try_new(vec![9; 32])?;
    let hasher = Argon2PasswordHasher::new(
        PasswordPolicy::try_new(8, 128)?,
        Argon2Params::try_new(32, 1, 1)?,
    );
    let setup_service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        hmac_key.clone(),
        hasher,
    );
    let signup = setup_service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "overflow@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = setup_service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original,
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    setup_service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;

    let late_service = AuthService::new(
        store.clone(),
        FixedClock::new(UnixTimestampMicros::try_new(i64::MAX - 1)?),
        DeterministicSecretGenerator::new(),
        hmac_key,
        hasher,
    );
    let challenge_overflow = late_service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "overflow-challenge@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await;
    let challenge_overflow = match challenge_overflow {
        Ok(_) => return Err("overflowed challenge expiry should fail".into()),
        Err(error) => error,
    };
    assert_eq!(challenge_overflow.code(), AuthErrorCode::Internal);

    let session_overflow = late_service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "overflow@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let session_overflow = match session_overflow {
        Ok(_) => return Err("overflowed session expiry should fail".into()),
        Err(error) => error,
    };
    assert_eq!(session_overflow.code(), AuthErrorCode::Internal);

    let absolute_overflow_service = AuthService::new(
        store.clone(),
        FixedClock::new(UnixTimestampMicros::try_new(
            i64::MAX - ABSOLUTE_SESSION_MICROS + 1,
        )?),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let absolute_overflow = absolute_overflow_service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "overflow@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let absolute_overflow = match absolute_overflow {
        Ok(_) => return Err("overflowed absolute session expiry should fail".into()),
        Err(error) => error,
    };
    assert_eq!(absolute_overflow.code(), AuthErrorCode::Internal);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn service_maps_secret_generation_failures_to_internal_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let hmac_key = HmacSecretKey::try_new(vec![9; 32])?;
    let hasher = Argon2PasswordHasher::new(
        PasswordPolicy::try_new(8, 128)?,
        Argon2Params::try_new(32, 1, 1)?,
    );
    let setup_service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        hmac_key.clone(),
        hasher,
    );
    let signup = setup_service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "generator-failure@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = setup_service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original,
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    setup_service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;

    let failing_service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        FailingSecretGenerator,
        hmac_key,
        hasher,
    );
    let signup_failure = failing_service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "new-generator-failure@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await;
    let signup_failure = match signup_failure {
        Ok(_) => return Err("signup id generation should fail".into()),
        Err(error) => error,
    };
    assert_eq!(signup_failure.code(), AuthErrorCode::Internal);

    let challenge_failure = failing_service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "generator-link@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await;
    let challenge_failure = match challenge_failure {
        Ok(_) => return Err("challenge secret generation should fail".into()),
        Err(error) => error,
    };
    assert_eq!(challenge_failure.code(), AuthErrorCode::Internal);

    let session_failure = failing_service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "generator-failure@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let session_failure = match session_failure {
        Ok(_) => return Err("session token generation should fail".into()),
        Err(error) => error,
    };
    assert_eq!(session_failure.code(), AuthErrorCode::Internal);

    let fail_after_first_service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        FailAfterFirstSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let challenge_id_failure = fail_after_first_service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "generator-challenge-id@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await;
    let challenge_id_failure = match challenge_id_failure {
        Ok(_) => return Err("challenge id generation should fail".into()),
        Err(error) => error,
    };
    assert_eq!(challenge_id_failure.code(), AuthErrorCode::Internal);

    let fail_after_first_service = AuthService::new(
        store,
        FixedClock::new(now()),
        FailAfterFirstSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let session_id_failure = fail_after_first_service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "generator-failure@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let session_id_failure = match session_id_failure {
        Ok(_) => return Err("session id generation should fail".into()),
        Err(error) => error,
    };
    assert_eq!(session_id_failure.code(), AuthErrorCode::Internal);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn email_challenge_signin_creates_verified_account_and_session()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store,
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "link@example.com".to_owned(),
            user_id: None,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;

    let signin = service
        .sign_in_with_email_challenge(harbor_core::EmailChallengeSignInInput {
            challenge_id: challenge.challenge.id,
            secret: challenge.secret,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;

    assert!(signin.email.verified_at.is_some());
    assert_eq!(
        signin.redirect_path,
        Some(RedirectPath::try_new("/account")?)
    );
    assert!(
        service
            .current_session(&signin.session_token)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn passwordless_email_accounts_do_not_receive_password_reset()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let hmac_key = HmacSecretKey::try_new(vec![9; 32])?;
    let service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        hmac_key.clone(),
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let signin_challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "passwordless@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await?;
    let signin = service
        .sign_in_with_email_challenge(harbor_core::EmailChallengeSignInInput {
            challenge_id: signin_challenge.challenge.id,
            secret: signin_challenge.secret,
            redirect_path: None,
        })
        .await?;

    let reset = service
        .request_password_reset(harbor_core::RequestPasswordResetInput {
            email: "passwordless@example.com".to_owned(),
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
        })
        .await?;
    assert_eq!(reset.challenge, None);

    let reset_secret = SecretToken::try_new("reset-secret")?;
    let reset_id = ChallengeId::try_new("challenge00000200")?;
    store
        .create_challenge(CreateChallengeInput {
            id: reset_id.clone(),
            purpose: ChallengePurpose::PasswordReset,
            user_id: Some(signin.email.user_id),
            email_canonical: EmailAddress::parse("passwordless@example.com")?
                .canonical()
                .clone(),
            secret_hash: hash_secret_token(&hmac_key, SecretHashPurpose::UrlToken, &reset_secret)?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
            expires_at: UnixTimestampMicros::try_new(60_000_000)?,
            max_attempts: RetryBudget::try_new(5)?,
            resend_after: now(),
            now: now(),
        })
        .await?;
    let reset = service
        .reset_password(harbor_core::ResetPasswordInput {
            challenge_id: reset_id,
            secret: reset_secret,
            new_password: "new correct horse battery staple".to_owned(),
        })
        .await;
    let reset = match reset {
        Ok(_) => return Err("passwordless reset should not set a first password".into()),
        Err(error) => error,
    };
    assert_eq!(reset.code(), AuthErrorCode::InvalidCredentials);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn email_challenge_signin_verifies_existing_unverified_account()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store,
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "existing-link@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    assert!(signup.email.verified_at.is_none());

    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "EXISTING-LINK@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await?;
    let signin = service
        .sign_in_with_email_challenge(harbor_core::EmailChallengeSignInInput {
            challenge_id: challenge.challenge.id,
            secret: challenge.secret,
            redirect_path: None,
        })
        .await?;

    assert_eq!(signin.email.user_id, signup.user.id);
    assert!(signin.email.verified_at.is_some());
    assert!(
        service
            .current_session(&signin.session_token)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn email_challenge_signin_reuses_existing_verified_account()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store,
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "verified-link@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original,
            user_id: Some(signup.user.id.clone()),
            redirect_path: None,
        })
        .await?;
    service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;

    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "VERIFIED-LINK@example.com".to_owned(),
            user_id: None,
            redirect_path: None,
        })
        .await?;
    let signin = service
        .sign_in_with_email_challenge(harbor_core::EmailChallengeSignInInput {
            challenge_id: challenge.challenge.id,
            secret: challenge.secret,
            redirect_path: None,
        })
        .await?;

    assert_eq!(signin.email.user_id, signup.user.id);
    assert!(signin.email.verified_at.is_some());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn password_reset_rejects_version_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store.clone(),
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "version-overflow@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original.clone(),
            user_id: Some(signup.user.id.clone()),
            redirect_path: None,
        })
        .await?;
    service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;
    let reset = service
        .request_password_reset(harbor_core::RequestPasswordResetInput {
            email: signup.email.email_original,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
        })
        .await?;
    let reset = match reset.challenge {
        Some(challenge) => challenge,
        None => return Err("verified email should produce reset challenge".into()),
    };
    sqlx::query("UPDATE harbor_password_credentials SET password_version = ?1 WHERE user_id = ?2")
        .bind(i64::MAX)
        .bind(signup.user.id.as_str())
        .execute(store.pool())
        .await?;

    let overflow = service
        .reset_password(harbor_core::ResetPasswordInput {
            challenge_id: reset.challenge.id,
            secret: reset.secret,
            new_password: "new correct horse battery staple".to_owned(),
        })
        .await;
    let overflow = match overflow {
        Ok(_) => return Err("password version overflow should fail".into()),
        Err(error) => error,
    };
    assert_eq!(overflow.code(), AuthErrorCode::Internal);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn password_reset_service_is_enumeration_resistant_and_revokes_sessions()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = AuthService::new(
        store,
        FixedClock::new(now()),
        DeterministicSecretGenerator::new(),
        HmacSecretKey::try_new(vec![9; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );

    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "reset@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original.clone(),
            user_id: Some(signup.user.id.clone()),
            redirect_path: None,
        })
        .await?;
    service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;

    let signin = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "reset@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await?;
    assert!(
        service
            .current_session(&signin.session_token)
            .await?
            .is_some()
    );

    let unknown = service
        .request_password_reset(harbor_core::RequestPasswordResetInput {
            email: "unknown@example.com".to_owned(),
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    assert_eq!(unknown.challenge, None);

    let reset_request = service
        .request_password_reset(harbor_core::RequestPasswordResetInput {
            email: "RESET@example.com".to_owned(),
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    let reset_challenge = match reset_request.challenge {
        Some(challenge) => challenge,
        None => return Err("verified email should receive a reset challenge".into()),
    };

    let reset = service
        .reset_password(harbor_core::ResetPasswordInput {
            challenge_id: reset_challenge.challenge.id,
            secret: reset_challenge.secret,
            new_password: "new correct horse battery staple".to_owned(),
        })
        .await?;
    assert_eq!(reset.credential.password_version, 2);
    assert_eq!(reset.revoked_sessions, 1);
    assert_eq!(
        reset.challenge.redirect_path,
        Some(RedirectPath::try_new("/account")?)
    );
    assert_eq!(service.current_session(&signin.session_token).await?, None);

    let old_password = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "reset@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await;
    let old_password = match old_password {
        Ok(_) => return Err("old password should fail after reset".into()),
        Err(error) => error,
    };
    assert_eq!(old_password.code(), AuthErrorCode::InvalidCredentials);

    let new_password = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "reset@example.com".to_owned(),
            password: "new correct horse battery staple".to_owned(),
            redirect_path: None,
        })
        .await?;
    assert!(
        service
            .current_session(&new_password.session_token)
            .await?
            .is_some()
    );
    Ok(())
}
