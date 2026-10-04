# Authentication and identity

au-geocoder serves two audiences with different credentials:

| Audience | Surface | Credential |
|----------|---------|------------|
| API callers | `/search`, `/geocode`, `/reverse`, `/poi`, `/parse`, `/suggest`, `/batch` | `X-Api-Key`, an OIDC/OAuth2 access token (`Authorization: Bearer <JWT>`), or nothing (anonymous tier) |
| People | `/console/*`, `/auth/*` | A server-side session established by SSO (OIDC, GitHub, SAML) or a passkey |
| Identity providers | `/scim/v2/*`, back-channel logout | A per-org SCIM bearer token; a signed logout token |

There are no passwords anywhere. A person proves who they are through an
identity provider or a passkey they registered after an SSO login.

The console is off unless `AUGEO_PUBLIC_URL` and `AUGEO_SECRET_KEY` are set.
With it off, the service behaves exactly as before: operator keys from
`keygen`, anonymous access, and (if issuers are configured by an operator)
bearer tokens.

## Principles

- **Fail closed.** Unknown issuer, bad signature, missing audience, expired
  token, revoked key, suspended user, unverifiable email: all deny.
- **Uniform API errors (T6).** Every API credential failure is the same 401
  body. The API never says which part failed. Details go to the log as a
  reason code, never as a credential or a query.
- **Tenant isolation is checked in the store, not the handler.** Every
  org-scoped store method takes the org ID and includes it in the `WHERE`
  clause. A handler cannot fetch a key, connection or member by ID alone.
- **No query retention (INV-1, T7, T9) still holds.** Identity data is about
  people and orgs; it never includes geocoding queries. IP addresses are not
  stored in sessions or the audit log.
- **Secrets at rest are encrypted.** OIDC client secrets and SAML SP private
  keys are sealed with AES-256-GCM under `AUGEO_SECRET_KEY`. Session IDs,
  API keys and SCIM tokens are stored only as hashes.

## Model

```
org ──< membership >── user ──< identity (connection, subject)
 │                       └──< passkey
 ├──< sso_connection (oidc | github | saml)  ── group→role mappings
 ├──< domain (DNS-verified)
 ├──< api_key
 ├──< jwt_issuer
 ├──< scim_token, scim_group ──< scim_group_member
 ├──< invite
 └──< audit_event
```

Connections with no org are **platform connections** (for example "Sign in
with Google" for anyone). Connections with an org are **org connections**
(the org's own Entra, Okta or SAML IdP).

### Roles

| Role | Can |
|------|-----|
| `viewer` | See the org, its usage, members and key metadata |
| `developer` | + create API keys, revoke keys they created |
| `admin` | + manage all keys, members, invites, domains, JWT issuers; read the audit log |
| `owner` | + SSO connections, group mappings, SCIM tokens (whoever controls the org's IdP or SCIM feed decides its members and roles), org settings (SSO enforcement, JIT, default role), delete the org. The last owner cannot be removed or demoted |

Platform admins (`users.platform_admin`) manage platform connections, all
orgs (including each org's quota tier) and users. The first platform admins
come from `AUGEO_AUTH_BOOTSTRAP_ADMINS`, a list of emails promoted on their
first login through a connection that is trusted for email.

## Login

### Flow binding

Every interactive flow (OIDC, GitHub, SAML) writes an `auth_flow` row keyed by
`SHA-256(state)` holding the connection, nonce, PKCE verifier, SAML request
ID, return path and a 10-minute expiry. The browser also gets a
`__Host-augeo_flow` cookie with a random binding value stored in the row. The
callback requires the cookie to match, which stops an attacker from
completing a flow they started in someone else's browser (login CSRF). The
row is deleted on first use.

`return_to` must be a relative path starting with `/console`; anything else
becomes `/console`.

### OIDC

- Authorization code flow with PKCE (S256), `state` and `nonce`.
- Discovery from `{issuer}/.well-known/openid-configuration`; the ID token's
  `iss`, `aud`, `exp`, `nonce` and signature are verified by go-oidc. If the
  authorization response carries `iss` (RFC 9207), it must equal the
  connection's issuer (mix-up defence).
- Claims used: `sub`, `email`, `email_verified`, `name`, `sid`, and the
  connection's groups claim (default `groups`).
- Presets fill in the issuer pattern, scopes, groups claim and whether email
  can be trusted:

| Preset | Issuer | Email trusted for account linking |
|--------|--------|-----------------------------------|
| `google` | `https://accounts.google.com` | Yes, when `email_verified` |
| `entra` | `https://login.microsoftonline.com/{tenant}/v2.0` | **No** (the `email` claim is user-editable in many tenants). Linking needs a verified domain on an org connection |
| `okta` | `https://{domain}` or `https://{domain}/oauth2/{server}` | When `email_verified` |
| `auth0` | `https://{domain}/` | When `email_verified` |
| `keycloak` | `https://{host}/realms/{realm}` | When `email_verified` |
| `gitlab` | `https://gitlab.com` or self-hosted | When `email_verified` |
| `zitadel`, `authentik` | Instance URL | When `email_verified` |
| `generic` | Any | When `email_verified` |

### GitHub

GitHub is OAuth2, not OIDC. The callback exchanges the code (with PKCE),
calls `/user` for the stable numeric ID (the subject) and `/user/emails` for
the primary **verified** email. Org restriction is available through the
connection's `allowed_orgs` (checked against `/user/orgs`, which needs the
`read:org` scope).

### SAML 2.0

SP-initiated, HTTP-Redirect binding for the request (signed, RSA-SHA256)
and HTTP-POST for the response. Each SAML connection has its own SP entity ID
(`/auth/saml/{slug}/metadata`, which also serves the SP metadata) and ACS URL
(`/auth/saml/{slug}/acs`), its own signing key pair (generated on creation,
private key sealed) and stores the IdP metadata XML. Assertions must be
signed (a signed response covering them is also accepted), `InResponseTo`
must match the flow's request ID, and audience, `NotBefore`/`NotOnOrAfter`
(180 s skew), issue time (90 s), recipient and destination are checked by
crewjam/saml. Encrypted assertions are accepted; the artifact binding is not.
IdP-initiated SSO is refused, because it cannot be bound to a flow. The NameID
is the subject, so a transient NameID is refused.

Attribute mapping per connection: email (default NameID if its format is
emailAddress or it contains `@`, else `email`, `mail`,
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` or
`urn:oid:0.9.2342.19200300.100.1.3`), name (default `displayName`, `name`,
`cn` and their URI forms, else given name plus surname), and groups (default
`groups`, `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`,
`memberOf`). Attributes match on Name or FriendlyName, ignoring case.

SAML single logout is not implemented; ending the console session does not
end the IdP session. Use SCIM deprovisioning or short session lifetimes for
prompt revocation.

### Resolving a login to a user

All three protocols produce the same `Assertion` (connection, subject, email,
email-trusted flag, name, groups, IdP session ID), and one function turns it
into a user:

1. **Known identity.** If `(connection, subject)` exists, that is the user.
2. **Org connection.** The email domain must be a verified domain of the
   connection's org; otherwise deny. Find the user by email or, if the org
   has JIT on (or an invite exists), create one. An existing user is linked
   only if they have no access outside this org (no other org except their
   own personal workspace, not a platform admin); otherwise deny, because the
   org's IdP decides what email it asserts. Pending invites from this org
   are accepted. Multi-tenant Entra issuers (`common`, `organizations`,
   `consumers`) are refused on org connections, and changing a connection's
   issuer, client ID or SAML metadata drops its linked identities and
   sessions.
3. **Platform connection.** If the email's domain is verified by an org with
   SSO enforcement, deny and point the user to that org's SSO. Otherwise, if
   the email is trusted, link to an existing user with that email or create
   one (when `AUGEO_AUTH_SIGNUP=open`, or when an invite or bootstrap entry
   exists). If the email is **not** trusted and a user with that email already
   exists, deny: linking on an unverified email is how accounts get taken over.
4. **Status.** Suspended or deprovisioned users are denied.
   Bootstrap admins are promoted once, when their account is created; a
   later revocation sticks.
5. **Group mappings.** For org connections with mappings, the member's role
   becomes the highest role whose group appears in the assertion; with no
   match, the org's default role (JIT) or the existing manual role.
6. A brand-new user with no membership gets a personal org where they are
   owner, so a self-signup user can create keys at once.

### Sessions

- 256-bit random ID in `__Host-augeo_session` (`Secure`, `HttpOnly`,
  `SameSite=Lax`, `Path=/`). Only `SHA-256(id)` is stored.
- A new ID on every login (no fixation). Idle timeout 8 h, absolute 7 days
  (`AUGEO_AUTH_SESSION_IDLE`, `AUGEO_AUTH_SESSION_MAX`).
- Each session has a CSRF token. Every state-changing console request must
  be `POST` with a matching `csrf` field or `X-CSRF-Token` header, and an
  `Origin` (or `Referer`) equal to `AUGEO_PUBLIC_URL`.
- Users can list and revoke their own sessions. Suspension, SCIM
  deprovisioning and back-channel logout delete sessions immediately.

### Logout

- `POST /auth/logout` deletes the session. For OIDC connections that publish
  `end_session_endpoint`, the browser is redirected there with
  `id_token_hint` and `post_logout_redirect_uri`.
- **Back-channel logout** (OIDC): `POST /auth/oidc/{id}/backchannel-logout`
  with a `logout_token` form field. The token is verified against the
  connection's keys; `iss`, `aud`, `iat`, the back-channel `events` member and
  the absence of `nonce` are checked, `jti` is recorded to refuse replays,
  and sessions matching `sid` (or `sub` if no `sid`) are deleted.

### Passkeys

WebAuthn passkeys (go-webauthn) can be registered by a signed-in user and
used as a login method afterwards, through discoverable credentials. They are
meant for break-glass access when an IdP is down, so:

- A user in an org with SSO enforcement can sign in with a passkey only if
  they are an owner of that org or a platform admin. Owners are not exempt
  from enforcement on platform IdP logins; the passkey is their break-glass
  path.
- Registration requires a session younger than 10 minutes (fresh SSO login).
- User verification is required; the sign count is checked for clones.

## Domain verification

An org admin adds a domain and gets a token. The domain verifies when
`_augeo-verify.<domain>` has a TXT record `augeo-verify=<token>`. A domain can
be verified by one org only. Verified domains drive org-connection login
(rule 2), home-realm discovery on the login page ("Continue with work
email") and SSO enforcement (rule 3).

## SCIM 2.0

`/scim/v2` with an org SCIM token as `Authorization: Bearer`. Implements
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Users` and `Groups`:
create, get, list with `filter` (`eq` on `id`, `userName`, `externalId`,
`emails.value`, `emails[type eq "work"].value` for users; `id`,
`displayName`, `externalId` for groups; joined by `and`/`or` with
parentheses) and `startIndex`/`count` (count capped at 200), replace (`PUT`),
`PATCH` (including Entra's capitalised ops, path-less value objects,
`name.givenName`-style paths and `"True"`/`"False"` string booleans) and
delete. Bulk, sort, ETags and `/.search` are not supported. Every request is
scoped to the token's org; another org's IDs answer 404. Bodies are capped
at 1 MiB. Unknown attributes (enterprise extension, `title`, phone numbers)
are accepted and ignored.

- `userName` is the email. SCIM may only provision an address whose domain
  is a **verified domain of the token's org**; anything else is 400
  `invalidValue`. Domains verify to one org only, so a SCIM token can never
  create, link or rename an account outside its org's domains. The check
  applies to new addresses only, so an org that drops a domain can still
  deactivate its users.
- Creating a user whose email already exists links that user (409
  `uniqueness` if already provisioned in this org) and adds an org
  membership with source `scim` and the role from SCIM group mappings, else
  the org default role. An existing membership (e.g. manual) is kept as is.
- The SCIM `id` is a random UUID (`scim_users.scim_id`), never the database
  user ID. Name parts, `displayName`, `externalId`, emails and `active` are
  stored per org in `scim_users` and returned as sent.
- The global user row (`users.email`, `users.name`) only changes when the
  user belongs to no other org and is not a platform admin; changing
  `userName` for a shared user is 400 `mutability`.
- `active: false` or `DELETE` removes the org membership (any source) and
  deletes all the user's sessions; a user left with no memberships and no
  platform role is marked deprovisioned. `active: true` (or re-creating
  after delete) restores the membership and reactivates a deprovisioned
  user. Removing the org's last owner is 400 and changes nothing.
- Group members must be SCIM users of the same org (400 otherwise). After any
  group change the affected users' roles are recomputed from SCIM group
  mappings (matched on `displayName`): highest mapped role, else the org
  default. Only memberships with source `scim` follow groups; manual,
  invite and other memberships are never changed. A change that would
  demote the last owner is refused as a whole. Group `PATCH` answers 204.
- Tokens are shown once, stored hashed, revocable, and every SCIM write is
  audited with actor `scim` (`scim.user.create`, `.update`, `.deactivate`,
  `.reactivate`, `.delete`, `scim.group.create`, `.update`, `.delete`).
  Mapping edits in the console apply at the next SCIM change for each user.

## API: bearer tokens

An org admin registers a **JWT issuer**: issuer URL, required audience,
optional JWKS URL (else discovery), scope prefix, and an optional subject
allowlist. Machine clients use the client-credentials grant at their own IdP
and call the API with `Authorization: Bearer <access token>`.

Validation: the issuer (read from the unverified token only to choose the
key set) must match an enabled issuer row; signature via the issuer's JWKS
(RS256, RS384, RS512, PS256, ES256, ES384, EdDSA; never `none` or HMAC); `aud`
contains the configured audience; `exp`/`nbf` with 60 s skew; scopes from
`scope` (space-separated) or `scp` (array), with the prefix stripped, must
include the endpoint's scope (`search` or `batch`).

The principal is `jwt:<issuer id>:<sub>`. Rate limits apply per principal;
the daily row quota is charged to the org at the org's tier. A request with
both `X-Api-Key` and `Authorization` is a 400.

## API keys

Keys keep the T6 design: random, `SHA-256(key ‖ pepper)` with a non-secret
prefix index and constant-time comparison. New:

- Keys created in the console belong to an org (`org_id`), record their
  creator, take the org's tier and can carry an expiry. Their raw value is
  shown once.
- Revocation in the console updates the in-memory index at once.
- `keygen` still issues operator keys with no org; those are unchanged.

T6's "no HTTP issuance endpoint" is replaced by: issuance only through an
authenticated console session with the `developer` role or above, CSRF and
origin checks, and an audit event.

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `AUGEO_PUBLIC_URL` | (unset: console off) | External base URL, e.g. `https://geo.example.com`. Used for redirect URIs, SAML entity IDs, the origin check and WebAuthn RP ID |
| `AUGEO_SECRET_KEY` / `_FILE` | (required with console) | 32 bytes, hex or base64. Seals client secrets and SAML keys |
| `AUGEO_AUTH_SIGNUP` | `closed` | `open` lets anyone with a trusted email through a platform connection create an account |
| `AUGEO_AUTH_BOOTSTRAP_ADMINS` | | Comma-separated emails made platform admin on first trusted login |
| `AUGEO_AUTH_SESSION_IDLE` | `28800` | Seconds |
| `AUGEO_AUTH_SESSION_MAX` | `604800` | Seconds |
| `AUGEO_AUTH_PROVIDERS_FILE` | | JSON list of platform connections to upsert at boot (see below) |

Platform connections can be managed in the admin console or declared in the
providers file so deployments are reproducible:

```json
[
  {"slug": "google", "preset": "google", "name": "Google",
   "client_id": "…apps.googleusercontent.com", "client_secret_file": "/run/secrets/google"},
  {"slug": "github", "kind": "github", "name": "GitHub",
   "client_id": "Iv1.…", "client_secret_env": "GITHUB_SECRET"}
]
```

## Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/auth/login` | GET | Login page: platform connections, passkey, work-email discovery |
| `/auth/discover` | POST | Work email → org connection redirect |
| `/auth/oidc/{id}/start` | GET | Begin OIDC or GitHub login |
| `/auth/oidc/callback` | GET | OIDC/GitHub redirect URI (one per deployment) |
| `/auth/oidc/{id}/backchannel-logout` | POST | OIDC back-channel logout |
| `/auth/saml/{id}/metadata` | GET | SP metadata for the IdP admin |
| `/auth/saml/{id}/start` | GET | Begin SAML login |
| `/auth/saml/{id}/acs` | POST | Assertion consumer service |
| `/auth/passkey/login/begin`, `/finish` | POST | Passkey login |
| `/auth/logout` | POST | End session (RP-initiated logout where supported) |
| `/console/…` | GET/POST | Web console |
| `/scim/v2/…` | various | SCIM 2.0 |

## Audit

`audit_events` records who did what to which object in which org: logins
(success and denial reason), session revocations, key issue/revoke, member
and role changes, connection, domain, mapping, issuer and SCIM-token changes,
SCIM writes, org settings, platform admin actions. Rows hold IDs and short
labels, never secrets, raw tokens or queries.

## Threat model additions

| ID | Threat | Guard |
|----|--------|-------|
| A1 | Login CSRF / session fixation | Flow-binding cookie; new session ID per login; a sign-in start that did not come from this site (`Sec-Fetch-Site`) shows a confirmation page whose button POSTs back, origin-checked |
| A2 | Account takeover via unverified email claim (nOAuth) | Email trusted per preset and `email_verified`; org connections require a verified domain; no linking on untrusted email |
| A3 | IdP mix-up | One callback URL, connection chosen by state, RFC 9207 `iss` check, ID token `iss` check |
| A4 | Open redirect after login | `return_to` restricted to `/console…` relative paths |
| A5 | Cross-org access in the console | Org ID in every store query; role checks in one middleware; tests that try each object type across orgs |
| A6 | Forged or replayed back-channel logout | Signature, `iss`/`aud`/`events`, no `nonce`, `jti` replay table |
| A7 | SAML XML signature wrapping, replay, IdP-initiated injection | crewjam/saml validation, signed assertions required, `InResponseTo` bound to the flow, IdP-initiated refused |
| A8 | JWT algorithm confusion | Asymmetric allowlist; keys only from the issuer's JWKS; issuer must be pre-registered |
| A9 | SCIM token theft | Hashed at rest, org-scoped, revocable, audited; SCIM can only touch its own org |
| A10 | Stolen session cookie | `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`; idle and absolute expiry; user-visible session list |
| A11 | Secrets exposure via DB copy | Client secrets and SAML keys sealed with `AUGEO_SECRET_KEY`; tokens hashed |

## Invites

An invite is always a pending row, even for an email that already has an
account: the person joins when they next sign in with a trusted address, so
nobody is added to an org without acting, and the response never reveals
whether an account exists. Invites expire after 14 days.
