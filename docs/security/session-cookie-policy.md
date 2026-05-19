# Session Cookie Policy

Date: 2026-05-18

## Summary

Harbor v0.1 uses opaque server-side sessions. The browser receives only a
session cookie containing an unguessable token. The database stores only a hash
of that token.

Harbor does not store auth tokens in `localStorage` or `sessionStorage`.

## Production Cookie Defaults

- Name: `__Host-harbor-session`
- `HttpOnly`: true
- `Secure`: true
- `SameSite`: `Lax` by default, configurable to `Strict`
- `Path`: `/`
- `Domain`: unset
- Persistent expiry: unset unless the application explicitly opts into a
  persistent session policy

The `__Host-` prefix requires Secure, no Domain attribute, and Path `/`. This
reduces cross-subdomain and downgrade risks.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Development Cookie Defaults

Local development may need non-HTTPS localhost support. Harbor must require an
explicit development cookie policy when production cookie settings cannot be
used. The development cookie name should not use the `__Host-` prefix unless
all prefix requirements are satisfied.

## CSRF

SameSite is defense in depth, not the only CSRF defense. Harbor v0.1 forms must
use HMAC-signed double-submit CSRF tokens for state-changing requests. The
submitted form token must match the CSRF cookie value and the token signature
must validate with the configured Harbor HMAC key.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Session Expiry

Default v0.1 policy:

- idle timeout: 12 hours;
- absolute timeout: 30 days;
- rotate on signin and sensitive transitions;
- revoke all sessions after password reset unless a future application policy
  explicitly chooses otherwise.

## Logging

Logs may include event kind, user id, canonical email, and stable redacted
detail codes. Logs must not include raw session tokens, challenge tokens, OTP
codes, password hashes, passwords, Resend API keys, or cookie values.
