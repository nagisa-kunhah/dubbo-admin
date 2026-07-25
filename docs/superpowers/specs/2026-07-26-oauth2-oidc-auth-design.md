# OAuth2/OIDC Authentication for Dubbo Admin

## Background

Dubbo Admin currently authenticates users with a single configured username and password, then stores the username in a Gin session. This is useful for local development, but it does not integrate with enterprise SSO and cannot reliably identify real users for audit, authorization, or future agent-driven operations.

Issue apache/dubbo-admin#1503 asks to introduce OAuth2 for Admin access and agent user identity. Because Dubbo Admin needs to know who the logged-in user is, the first implementation should use OpenID Connect (OIDC) on top of OAuth2 rather than plain OAuth2 alone.

## Goals

- Add OIDC login for the Admin web console.
- Keep the current username/password login for compatibility and local development.
- Store a normalized authenticated user identity in the server session.
- Add a fake OIDC provider for local development and e2e testing.
- Keep frontend token handling simple: the browser should use Dubbo Admin's session cookie, not store OAuth tokens.

## Non-Goals

- Do not store or rotate refresh tokens in phase 1.
- Do not implement agent bearer-token authentication in phase 1.
- Do not implement RBAC enforcement in phase 1.
- Do not support multiple OIDC providers in phase 1.
- Do not implement provider-specific logout in phase 1.

## Current Authentication

Current routes are registered under `/api/v1/auth` in `pkg/console/router/router.go`:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`

The login handler in `pkg/console/handler/auth.go` compares submitted form fields with `console.auth.user` and `console.auth.password`. On success, it writes `session["user"]`.

The global auth middleware in `pkg/console/component.go` checks for `session["user"]` and rejects unauthenticated requests with 401. The current skip rule only allows paths ending in `/login`, which is not sufficient for OIDC callback routes.

The Vue login page posts credentials from `ui-vue3/src/Login.vue` through `ui-vue3/src/api/service/login.ts`. The frontend also stores an `auth-state` cookie for client-side route decisions, but the real API authentication state is the server session.

## Phase 1 User Flow

1. A user opens the Dubbo Admin UI.
2. The login page shows password login and, when enabled, an SSO login action.
3. The user selects SSO login.
4. The browser navigates to `GET /api/v1/auth/oidc/login`.
5. Dubbo Admin generates `state`, `nonce`, and PKCE values, stores them temporarily in the session, and redirects the browser to the provider authorization endpoint.
6. The provider authenticates the user and redirects back to `GET /api/v1/auth/oidc/callback`.
7. Dubbo Admin validates `state`, exchanges the authorization code for tokens, validates the ID token, fetches or derives user info, then writes the normalized principal into the session.
8. The browser is redirected back to the Admin UI.
9. Subsequent API requests use the Dubbo Admin session cookie.

## Configuration

Extend console auth configuration to support both password and OIDC methods:

```yaml
console:
  auth:
    methods:
      - password
      - oidc
    user: admin
    password: dubbo@2025
    expirationTime: 3600
    oidc:
      issuer: http://localhost:9999
      clientId: dubbo-admin
      clientSecret: ${DUBBO_ADMIN_OIDC_CLIENT_SECRET}
      redirectUrl: http://localhost:8888/api/v1/auth/oidc/callback
      postLoginRedirectUrl: http://localhost:8881/admin/
      scopes:
        - openid
        - profile
        - email
      usernameClaim: preferred_username
      groupsClaim: groups
```

Phase 1 should support one OIDC provider and issuer discovery through `/.well-known/openid-configuration`. Manual endpoint overrides can be added later if a provider requires them.

`redirectUrl` is the callback registered with the OIDC provider. `postLoginRedirectUrl` is where Dubbo Admin sends the browser after the callback succeeds. In local development this will normally be the Vite UI URL; in deployment it will normally be the embedded `/admin/` UI path.

The session signing secret must become configurable. The current hardcoded value `"secret"` is acceptable only for local development.

## Backend API Changes

Add these endpoints:

- `GET /api/v1/auth/oidc/login`: starts the OIDC authorization-code flow.
- `GET /api/v1/auth/oidc/callback`: handles the provider callback and creates the local session.
- `GET /api/v1/auth/userinfo`: returns the current authenticated principal for the frontend.

Keep these endpoints:

- `POST /api/v1/auth/login`: password login.
- `POST /api/v1/auth/logout`: clears the local Dubbo Admin session.

Update the auth middleware to use an explicit anonymous-route allowlist instead of a suffix check. The allowlist should include password login, OIDC login, OIDC callback, and health checks. Business APIs under `/api/v1` should require an authenticated session.

## Principal Model

Replace direct use of `session["user"]` with a normalized principal:

```go
type Principal struct {
    Subject  string
    Username string
    Email    string
    Groups   []string
    Roles    []string
    AuthType string
    Provider string
}
```

For OIDC, `Subject` should come from `sub`. `Username` should come from the configured username claim, defaulting to `preferred_username`, then `email`, then `sub`. `Groups` and `Roles` should be stored for future authorization and audit, but phase 1 should not enforce RBAC.

For password login, create a principal with `AuthType: "password"` and `Username` from the submitted user.

## Frontend Changes

The login page should continue supporting username/password login. When OIDC is enabled, it should also show an SSO login action that navigates to `/api/v1/auth/oidc/login`.

After successful OIDC callback, the backend redirects to the Admin UI. The frontend should call `/api/v1/auth/userinfo` to populate displayed user identity and client route state instead of relying only on locally written `auth-state`.

The frontend must not store `access_token`, `id_token`, `refresh_token`, or client secrets.

## Fake OIDC Provider for Dev and E2E

Add a lightweight fake OIDC provider for local development and automated e2e tests. It should emulate the protocol boundary, not a full company SSO.

Recommended location:

- `test/fakeoidc/` for reusable Go test server code.
- `app/dubbo-admin/dubbo-admin-oidc-local.yaml` for local Admin configuration.

Minimum endpoints:

- `GET /.well-known/openid-configuration`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `GET /userinfo`
- `GET /jwks`

The authorize endpoint should auto-approve test users and redirect back with `code` and the original `state`. The token endpoint should exchange known test codes for deterministic tokens. The userinfo endpoint should return a stable test user such as:

```json
{
  "sub": "user-123",
  "preferred_username": "zhangsan",
  "email": "zhangsan@example.com",
  "groups": ["dubbo-admins"]
}
```

The fake provider should support at least:

- Happy path login.
- Invalid code.
- State mismatch.
- Missing or malformed user info.

## Test Plan

Backend tests should cover:

- Unauthenticated business API request returns 401.
- Password login still creates a valid session.
- OIDC login redirects to the provider authorization endpoint.
- OIDC callback rejects invalid state.
- OIDC callback rejects invalid code.
- Valid OIDC callback creates a principal session.
- Authenticated business API request succeeds.
- Logout clears the session.

E2E tests should run Dubbo Admin with an OIDC local config and the fake provider, then verify:

- User can start SSO login from the login page.
- Fake provider callback completes login.
- UI displays the fake user's identity.
- API requests after login succeed.
- Logout removes access and redirects back to login.

## Security Considerations

- Validate `state` for CSRF protection.
- Use and validate `nonce` for OIDC ID token replay protection.
- Prefer authorization code flow with PKCE.
- Validate ID token issuer, audience, signature, expiration, and nonce.
- Never expose `clientSecret` or OAuth tokens to frontend storage.
- Use HttpOnly and SameSite session cookies; use Secure cookies when served over HTTPS.
- Make session secret configurable and reject production startup with the default secret when OIDC is enabled.

## Future Phases

Agent authentication should be designed separately after Admin OIDC login is stable. The likely next step is accepting bearer tokens on API requests and mapping them to the same `Principal` model. A later phase can distinguish delegated user identity from machine client identity.

Refresh tokens should only be introduced when Dubbo Admin or an agent must call external systems for a long time on behalf of a user. If added, refresh tokens must be stored server-side, encrypted, and backed by Redis or a database instead of browser storage.

RBAC can build on the stored `Groups`, `Roles`, and `AuthType` fields, but phase 1 should only persist identity and leave authorization behavior unchanged.
