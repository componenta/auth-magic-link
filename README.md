# Componenta Auth Magic Link

Magic-link authentication for Componenta Auth 4.

The default browser profile is same-browser only. Requesting a link creates a
short-lived pre-authentication transaction. The delivery adapter must put both
the opaque one-time token and the public pre-auth transaction UUID (`binding`)
into the link.

The landing page POSTs both values to the verify endpoint while the browser also
presents the HttpOnly pre-auth cookie and memory-held request token. The binding
UUID must match that exact browser transaction before the one-time token is
consumed. This prevents login-CSRF/session-swapping and intentionally does not
model cross-device magic links.

One-time bearer persistence is delegated to `componenta/auth-token`.

Magic-link evidence is intentionally classified as `one_time_link`, not as a
generic possession factor and not as phishing resistant. In particular, an
email-delivered link must not accidentally satisfy an assurance policy that
expects a cryptographic possession authenticator.

## Requirements

PHP 8.4 or newer and the coordinated Componenta Auth 4 dependencies:
`componenta/auth ^4.0.0`, `componenta/auth-session ^2.0.0` and
`componenta/auth-session-http ^3.0.0`. The browser transport uses
`componenta/http-csrf-middleware ^4.0.0`. Unsafe CSRF-protected requests require
valid Origin/Referer evidence and an admitted CSRF token.

Upgrade these packages together. Session issuance uses the shared Componenta
Auth session APIs. See [CHANGELOG.md](CHANGELOG.md) for migration details.

One-time bearer support requires `componenta/auth-token ^1.0.1`.
