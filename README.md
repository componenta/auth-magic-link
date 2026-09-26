# Componenta Auth Magic Link

Magic-link authentication for Componenta Auth 3.

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
