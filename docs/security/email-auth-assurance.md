# Email Auth Assurance

Date: 2026-05-18

## Summary

Harbor v0.1 supports email password reset, email signup confirmation, email OTP,
and email magic links. These flows are useful and ergonomic, but they are not
phishing-resistant and they are not MFA.

## Standards Position

NIST SP 800-63B-4 says email must not be used as an out-of-band authenticator.
It also notes that confirmation codes for validating email addresses and
recovery codes are separate from that prohibition.

Source: https://pages.nist.gov/800-63-4/sp800-63b.html

Therefore Harbor v0.1 treats email OTP and magic links as single-factor
email-possession signin methods. Harbor documentation and APIs must not describe
them as MFA or NIST out-of-band authentication.

## v0.1 Claims

Harbor v0.1 may claim:

- verified control of an email inbox at the time of challenge completion;
- a convenient passwordless signin option;
- an email-based account recovery pathway;
- server-side session continuity after a successful auth flow.

Harbor v0.1 must not claim:

- MFA;
- phishing resistance;
- AAL2 compliance;
- possession of a device-bound authenticator;
- identity proofing.

## Required Controls

Every email challenge must be:

- generated with cryptographically secure randomness;
- long enough to resist brute force;
- hashed before storage;
- single use;
- time limited;
- attempt limited;
- rate limited by canonical email and request fingerprint;
- enumeration-resistant in request responses.

Password reset must not automatically create a session after a password is set.
OWASP recommends that users log in through the usual mechanism after reset.

Sources:

- OWASP Forgot Password Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Demo Implication

The `issuecertificate.com` demo can show email OTP and magic-link flows, but the
UI copy should describe them as email signin methods, not enhanced assurance.
