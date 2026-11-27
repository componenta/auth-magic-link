# Changelog

## Unreleased (3.0.0)

### Dependency compatibility

- Require Componenta Auth 4, Auth Session 2 and Auth Session HTTP 3, including
  the CSRF 4 browser transport. Upgrade the authentication packages together;
  the previous Auth 3 and Session HTTP 2 dependency families are incompatible.
- Require `componenta/identity ^1.1.1`.
- Require `componenta/auth-http ^2.0.0` for the shared credential transport.
- Require `componenta/auth-token ^1.0.1` for corrected token lifecycle handling.

## v2.0.0 (2026-10-10)

### Dependency compatibility
- Upgrade required `componenta/auth-session-http` from `^1.0` to `^2.0.1`; this adopts `componenta/http-csrf-middleware ^3.0` transitively.
- Keep the one-use magic-link authentication public contracts while sharing Componenta Auth sessions and their existing issuer.
- Update the main branch alias to `2.0.x-dev`.

### Migration
- Update the browser session transport and CSRF middleware as a compatible set; this major release cannot be installed with the old session-http 1.x family.
- Unsafe CSRF-protected browser operations require valid Origin/Referer and token validation; no permissive fallback is introduced.
- Verify actual session, account and CSRF flows after updating on PHP 8.4 / 8.5.

### Verification
- The release workflow checks Composer metadata, dependency advisories, PHPStan, and PHPUnit on PHP 8.4 and 8.5 before it publishes the stable GitHub tag.
