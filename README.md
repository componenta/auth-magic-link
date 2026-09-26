# Componenta Auth Magic Link

Magic-link authentication for Componenta Auth 3.

The default browser profile is same-browser only: verification requires the
short-lived pre-authentication cookie and request token from
`componenta/auth-session-http`. This prevents login-CSRF/session-swapping and
does not attempt to model cross-device magic links.

One-time bearer persistence is delegated to `componenta/auth-token`.
