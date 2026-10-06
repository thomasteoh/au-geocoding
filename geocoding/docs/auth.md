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

Single logout uses `/auth/saml/{slug}/slo`, advertised in the SP metadata
for the HTTP-Redirect and HTTP-POST bindings:

- **SP-initiated.** `POST /auth/logout` on a SAML session deletes the local
  session first. Then, if the IdP metadata lists a SingleLogoutService, it
  sends a signed LogoutRequest carrying the NameID with the `Format`,
  `NameQualifier` and `SPNameQualifier` from the login assertion (stored
  with the session; strict IdPs such as ADFS match on them) and the
  SessionIndex. HTTP-Redirect is preferred: the browser is redirected with
  the request signed in the query string (RSA-SHA256). If the IdP has only
  an HTTP-POST endpoint, the browser gets a page whose form posts the
  request, signed with an enveloped XML signature, to the IdP;
  `/console/static/autosubmit.js` submits it, and a Continue button does
  the same without JavaScript (the endpoint must be `https:`, which the
  CSP `form-action` allows). The request ID is recorded as a
  `saml-logout` flow bound to the browser's flow cookie (10 minutes). The
  IdP's LogoutResponse at the SLO URL must verify (see below), report
  success, and have an `InResponseTo` matching a pending request from this
  browser for this connection; the record is consumed on first use, match
  or not. The browser then lands on the login page with "You have signed
  out." Anything else gets a generic error page. The local session is gone
  either way. Without an IdP SLO endpoint, logout is local only.
- **IdP-initiated.** A LogoutRequest at the SLO URL ends the connection's
  sessions with that SessionIndex or, if it has none, that NameID. It is
  audited as `logout.saml_slo` and answered with a signed LogoutResponse
  (Success, RelayState echoed) on the IdP's SLO endpoint
  (`ResponseLocation` if given), by redirect or, for a POST-only IdP, by the
  same auto-submitting form. Request IDs are recorded to refuse replays.

Inbound logout messages must be signed by a signing certificate in the IdP
metadata, either on the redirect query (RSA-SHA256/384/512 over the
parameters as sent) or as an enveloped XML signature on the message; only
the signed element is read. The issuer must be the IdP entity ID,
`Destination` must be the SLO URL, `IssueInstant` must fall within the issue
window above (plus skew), and a request's `NotOnOrAfter` must not have
passed. Anything else is a 400 that touches no session and is audited as
`logout.saml_rejected` with a short reason code (`malformed`, `unsigned`,
`bad_signature`, `wrong_issuer`, `wrong_destination`, `stale`, `expired`,
`status_not_success`, `replay`, `unsolicited_response`, ...) and never the
message. Bodies and inflated
messages are capped at 1 MiB, and messages are never logged. For IdPs
without SLO, use SCIM deprovisioning or short session lifetimes for prompt
revocation.

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
  deprovisioning, back-channel logout and SAML single logout delete sessions
  immediately.

### Logout

- `POST /auth/logout` deletes the session. For OIDC connections that publish
  `end_session_endpoint`, the browser is redirected there with
  `id_token_hint` and `post_logout_redirect_uri`. For SAML connections whose
  IdP has an SLO endpoint, it is sent there with a signed
  LogoutRequest (redirect, or an auto-submitted POST form); IdP-initiated SAML logout arrives at
  `/auth/saml/{id}/slo` (see "SAML 2.0").
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
| `AUGEO_SMTP_HOST` | (unset: no invite emails) | SMTP submission server for invite emails. STARTTLS is required unless the host is `localhost` or a loopback address |
| `AUGEO_SMTP_PORT` | `587` | SMTP port (STARTTLS; implicit TLS on 465 is not supported) |
| `AUGEO_SMTP_USERNAME` | | Enables SMTP PLAIN auth (only over TLS, or to localhost) |
| `AUGEO_SMTP_PASSWORD` / `_FILE` | | SMTP password; redacted in the boot log |
| `AUGEO_SMTP_FROM` | (required with host) | Sender, `noreply@geo.example.com` or `Geocoder <noreply@geo.example.com>` |

When SMTP is configured, inviting someone emails them a plain-text message
naming the inviter, organisation, role, the `{AUGEO_PUBLIC_URL}/auth/login`
link and the expiry. A failed send never fails the invite: the console says
the email could not be sent and logs `invite_email_failed` with the org ID and
the error, never the recipient's address.

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
| `/auth/saml/{id}/slo` | GET/POST | SAML single logout service |
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

## Linking sign-in methods

A signed-in person can link another identity to their account from the
account page: they complete that provider's sign-in and the identity is
attached. Because they hold both, no email match is needed, which is what
lets someone who belongs to several orgs add each org's SSO (automatic
linking at login refuses accounts with access outside the org; see rule 2
above). Rules:

- Linking needs a recent SSO sign-in (within 10 minutes, not a passkey
  session), like adding a passkey.
- Only platform connections and connections of orgs the person belongs to
  are offered.
- An org connection link still needs the asserted email in a domain that
  org verified, and the org's invite, JIT and group-mapping rules apply.
- An identity already linked to another account cannot be linked again.
- Unlinking never removes the last way to sign in (identities plus
  passkeys), and ends sessions created through that connection.

## SSO enforcement

An org with SSO enforcement on checks every console request to its pages:
the session must have been created through one of that org's own
connections. Otherwise GETs show a page with the org's sign-in buttons and
other requests get 403. Exempt: platform admins, and owners on a passkey
session (break-glass). Because the check runs per request, sessions that
predate enforcement do not survive it, and guests at other domains need an
identity in the org's IdP (linked as above).

A session remembers every connection it has signed in through (session
proofs). Signing in again as the same person, for example into a second
enforced org's SSO, rotates the session ID but carries the earlier proofs
across with their original times, so one browser can work in several
enforced orgs. Proofs count only within the session lifetime they were
earned under, never move between different people's sessions, and are
dropped when the connection is deleted or unlinked.

Separately, platform IdP logins for an address in an enforced org's
verified domain are refused at sign-in. An owner can only turn enforcement
on from a session that already satisfies it, so they cannot lock
themselves out.

## Microsoft Entra ID

- Single-tenant issuer (`https://login.microsoftonline.com/{tenant}/v2.0`):
  go-oidc checks the token's issuer, so only that tenant signs in.
- Shared issuers (`common`, `organizations`): each token's issuer must be
  its own tenant's, and the connection's **allowed tenants** list pins
  which tenant IDs may sign in. The list is required on org connections and
  optional on platform connections; back-channel logout tokens are checked
  against it too.
- Email is trusted for linking only with the `xms_edov` claim (see the
  preset table).
- Group overage: when Entra omits groups (`_claim_names.groups` or
  `hasgroups`), the console asks Microsoft Graph (`/me/getMemberGroups`,
  needs GroupMember.Read.All consented). If that fails, the sign-in still
  works and the person's role is left unchanged rather than recomputed from
  an empty list.
