# 🔗 Anubis managed access

Shared managed-instance client and reverse Web gateway for Anubis-Security-Tool.
The client initiates outbound TLS connections; no public listener or firewall
opening is required on the managed PC. HTTP bodies and WebSocket streams travel
over authenticated per-request binary channels, including file transfers.

[Website](https://anubis.locker) · [Desktop](https://github.com/Anubis-Security-Tool/anubis) · [Web](https://github.com/Anubis-Security-Tool/anubis-web) · [Product Wiki](https://github.com/Anubis-Security-Tool/anubis/wiki)

This README describes the source in this repository, not a guarantee that an
installed desktop or Web release includes every capability described here.
Confirm the installed version and host support before relying on a feature.
The canonical product Wiki belongs to the desktop repository linked above;
linking to it does not mean that its pages have been initialized or published.

Enrollment, administrator approval, browser access and profile authentication are
separate boundaries. This transport does not reset Windows or application
passwords and does not turn SYSTEM/session 0 into an interactive desktop.

`createAgent` is exported from the package root; `createGateway` is exported from
`@ai-security-tool/managed-access/server`. Node 20 or newer is required.

## Package release

Version **1.0.4** includes workspace-password browser login, encrypted per-device
Web administrator roles, protected role issuance and User sign-out even on hosts
without Windows context controls. It preserves the functional source through
`eb0cfa015fadad018589f5060b99d749a586c598`; the earlier published `1.0.3`
does not identify this complete source revision.

After coordinated publication, Desktop and Web source installs must pin
`@ai-security-tool/managed-access` to `1.0.4` and update their lockfiles using
`https://npm.anubis.locker/`. Publishing this SDK alone does not update those
consumers or deploy a controller. Validate the package contents with
`npm pack --dry-run` before publishing; the package includes `context-ui.js`
and `web-credentials.js` as well as the client and gateway.

An installation persists a random UUID and 256-bit credential in its private
profile. The controller stores only its SHA-256 fingerprint. First enrollment is
**pending**, not trusted: an administrator must verify the fingerprint shown by the
local application and approve it. Reconnection preserves this decision. Revocation
closes active transport channels and invalidates browser sessions.

## Moving a user installation to a SYSTEM service

Managed identity is **profile-specific, not machine-specific**. Its fingerprint
is SHA-256 of the UTF-8 hex credential, not a hardware fingerprint. A different
private `identityFile` on the same PC creates an independent random UUID and
credential. No key-rotation or credential-replacement endpoint is needed.

1. Keep the original user profile and identity file intact. Give the service a
   fresh, persistent SYSTEM-owned profile and `identityFile`; restrict its Windows
   ACL to SYSTEM and the authorized administrators. The file's `mode: 0o600`
   creation option does not configure Windows ACLs. Do not copy the user identity,
   reuse its UUID, or expose the new credential in logs or operator reports.
2. Start the service with that fresh identity file. The client POSTs
   `/api/agents/enroll` with `{ id, secret, label, app, version, platform, arch }`.
   `id` is a lowercase UUID v4 and `secret` is 64 lowercase hex characters;
   metadata fields are optional strings, truncated to 128 characters. A new ID
   returns HTTP 201 with `{ id, status: "pending", fingerprint }`. This request
   does not need administrator authentication, but pending credentials cannot
   open tunnels or obtain access grants.
3. Independently verify the new ID and fingerprint reported by the SYSTEM
   service. An authenticated administrator lists records using
   `GET /api/agents` (response `{ agents: [...] }`) and explicitly approves the
   **new** ID using `POST /api/agents/:id/approve` with no body. Success returns
   HTTP 200 and the public agent record. The gateway delegates administrator
   authentication to its `isAdmin(req)` callback; the managed credential itself
   grants no administrator authority. Approval does not verify a fingerprint
   supplied in the request, so the administrator must verify before approving.
4. Wait for the new record to be approved and `online: true`, with the service's
   local readiness probe passing. Its device hostname changes with its new UUID.
   Open its device URL and sign in with the new profile's workspace password.
   Obtain fresh MCP grants when needed; grants from the legacy installation
   are not transferable.
5. Legacy approval, sessions and active channels remain unchanged. If retiring
   that access is separately authorized, an administrator can POST
   `/api/agents/:oldId/revoke`; revocation closes its active channels and
   invalidates browser/MCP grants and unused tickets. Do not revoke the original
   record merely to test migration or before verifying service availability.

Repeated enrollment with the same ID and secret returns HTTP 200 and preserves
`pending`, `approved` or `revoked` status; it may refresh the supplied metadata.
Using an existing ID with a different secret returns HTTP 409 without replacing
that record. Fingerprints are not deduplicated across different IDs: manually
reusing a secret under a new UUID would still enroll, so a genuinely fresh
service profile must generate **both** values. Approval and scopes are never
inherited from another record. Reuse the service's own identity file on restart;
do not regenerate it each time.

## Password-based browser access

Device hostnames are isolated as
`device-<installation-UUID-without-hyphens>.anubis.locker`; wildcard DNS and TLS
must be configured. Open the approved device's URL directly and sign in with
its **application workspace password**, not a Windows password or controller
administrator token. The default machine workspace is SYSTEM.

The gateway forwards a same-origin `POST /_anubis/login` password request through
the authenticated device tunnel to `POST /api/managed-password-login`. Only the
target application verifies the existing profile password. Passwords are not
stored in the controller or included in URLs. An unset profile password returns
409: configure it locally before using remote access. A bad password returns 401;
the gateway limits sign-in attempts to ten per device/source address per minute,
with an additional application-side limit.

Successful login creates a host-only HttpOnly, Secure, SameSite=Strict cookie,
valid for the configured `sessionMs` (eight hours by default). Reloading does not
require another controller grant or change the cookie. The gateway binds traffic
to the authenticated profile token and strips spoofed transport headers and stale
query tokens. `POST /_anubis/logout` revokes that browser session, closes its
channels and clears its cookie. The workspace bar and existing logout control
both invoke this operation.

Controller operators still authenticate separately for enrollment approval,
inventory and MCP grants. Existing short-lived controller navigation tickets
remain one-use, but **neither a device link nor a controller ticket authenticates
the workspace**. Ticket exchange alone cannot open HTTP APIs or WebSockets.
The gateway strips its cookie and reserved headers before forwarding.
Standalone Web authentication remains separate and unchanged.

Password sessions are held in memory: a gateway/application restart, password
change, expiry or revocation can require signing in again. This implementation
does not promise login persistence across process restarts. The updated desktop
adapter is required; an older desktop without the password-login endpoint fails
closed instead of falling back to passwordless access.

For external MCP clients, an administrator can POST
`/api/agents/:id/mcp-token` for an approved, online device. The response contains
`url`, `token`, `scope: "mcp"` and `expiresAt`. Supply the token as
`Authorization: Bearer <token>` to the returned HTTPS `/mcp` endpoint. It expires
after at most one hour and permits only GET, POST and DELETE on that device's exact
`/mcp` path, including query parameters. It cannot open the browser UI, controller
APIs or WebSockets. The gateway removes this credential before forwarding;
the application's private transport-authenticated adapter handles local MCP
authentication without uploading its local key. The local authenticated MCP
widget must actually be running. Expiration closes active HTTP/SSE streams;
revocation invalidates all browser and MCP grants and closes active channels.
MCP response headers may take up to 130 seconds, accommodating the existing
120-second synchronous command timeout; ordinary Web responses retain 30 seconds.

## Windows contexts in a managed browser

### Per-device Web roles (source integration contract)

Web roles are Anubis access roles, not Windows accounts. Both start in the
separate SYSTEM Web workspace; the ordinary Desktop user's profile is unchanged.
User is the default sign-in choice and cannot list or select Windows workspaces.
An explicitly authenticated Web administrator may use the existing policy-bound
context chooser. Selecting a profile discards the issued SYSTEM profile token;
the selected profile still requires its own application authentication.

The management administrator can configure a device's Web administrator password
using `GET /api/agents/:id/web-admin` and
`POST /api/agents/:id/web-admin {fingerprint,password,expectedRevision}`.
GET/POST return only `{configured,revision,updatedAt,role,workspace,userPasswordSource}`.
Only explicit `POST /api/agents/:id/web-admin/reveal {fingerprint}` returns that
Web password, with `Cache-Control: no-store`. The dashboard clears it after
15 seconds, closing settings, stale identity/inventory or management sign-out.
It does not retrieve Windows passwords, native profile passwords or user files.
Rotation uses compare-and-set revision checks and closes this device's
administrator Web sessions, not User sessions, enrollment or MCP grants.

Passwords must be unique, at least 16 bytes, at most 1024 bytes, with upper/lower
case, a number and a symbol; common/default patterns are refused. There is no
universal administrator or user credential. `web-admin.json` stores a random-salt
scrypt verifier (N=16384, r=8, p=1, 64-byte result) and AES-256-GCM ciphertext.
`web-admin.key` is an independent random 32-byte server key. Device ID, revision,
timestamp and verifier metadata are authenticated as GCM associated data.
Key/store files are created exclusively with mode 0600; existing nonprivate
POSIX modes, symlinks, missing keys, corruption and authenticated-data mismatch
fail closed. Run one writer process under a protected server data directory.
On Windows, provision a service-account/Administrators-only directory ACL
separately: POSIX mode does not configure Windows ACLs. Back up key and store
together through the existing private backup process; never commit either file.

Device sign-in is same-origin
`POST /_anubis/login {role:'user'|'administrator',password}`. Missing role means
User for older clients. Approval, rate limits, expiry and revocation still apply.
The gateway verifies the administrator password before calling the private
loopback adapter, and limits concurrent administrator KDF operations to four.
It never forwards the administrator password to a device.

Required App adapter:

* User: private `POST /api/managed-password-login {password}` verifies the
  protected `<app.getPath('userData')>\\web-user-password.txt` locally on each
  login and returns the existing 64-hex profile token only after protected
  backend authorization. Generate a distinct initial password locally if
  absent; local authorized edits take effect on the next login. No upload,
  central plaintext user-password storage, Windows password reset or DPAPI
  mutation is part of this protocol.
* Administrator: private `POST /api/managed-role-login
  {role:'administrator',bindingId:<64hex>,expiresAt:<integer>}` carries the
  agent-injected transport proof **and** `x-anubis-managed-session: bindingId`.
  App must reject missing/mismatched binding, nonadministrator role, expired
  assertions and expiry more than eight hours ahead. Only after its protected
  local authorization does it return exactly
  `{token:<64hex>,bindingId,role:'administrator',expiresAt}`.
* The gateway compares every response binding/role/expiry and the credential
  revision again before issuing a host-only HttpOnly Secure cookie. Missing or
  incompatible App support is an explicit failure, never passwordless fallback.
  Both adapter routes are blocked for decoded/canonical public device paths,
  including authenticated browsers. Browser-supplied managed-role/session
  headers are stripped. Internal role/user RPC functions must not be callable
  through ordinary browser RPC.

The server/UI source contract alone is not proof that the local verifier,
protected issuance or file-edit behavior is installed. Integrate and test the
matching App adapter before release. Preparing SDK 1.0.4 does not itself publish
the package or install its matching App adapter.
Project: https://github.com/Anubis-Security-Tool/anubis-managed-access.

A compatible Windows machine host can offer SYSTEM and policy-authorized
interactive Windows sessions. This is not an application administrator/user role
toggle, and standalone Web on Linux does not acquire Windows identities.
The device page loads `/_anubis/context-ui.js` only when the host supports this
contract. Its chooser displays the real Windows account, SID and session.

`GET /_anubis/contexts` requires the authenticated device browser cookie and
returns sanitized choices plus the current identity. `POST` to the same path
requires same-origin JSON containing only a listed opaque `id`. The gateway
requests the change through the SYSTEM transport, rotates its browser cookie
without extending its lifetime, and closes only that browser session's existing
HTTP/WebSocket channels. Other browsers remain in their own contexts. The
browser clears its old `tokenElecterm` and reloads; the selected Windows profile
still requires its own application password and retains its own DPAPI data.
An expired logon or failed selection never selects a fallback account.

The gateway strips browser-supplied `x-anubis-managed-session` and
`x-anubis-managed-context` headers. It supplies a random server-only session
binding and the host-issued selector on HTTP and WebSocket requests. The native
adapter revalidates Windows policy/logon identity, and loopback ports, transport
proofs and local tokens never reach the browser. The internal
`/api/machine-contexts` route cannot be called directly through the public
gateway. MCP-only grants cannot list or change contexts and remain SYSTEM scoped.
Cookie rotation preserves the server-only binding; the old cookie is revoked.

`createAgent` takes `baseUrl`, `identityFile`, `localPort`, optional fixed loopback
`localHost`, `label`, `app`, `version`, async `probe`, `onStatus`, and optional
`localHeaders`. The latter are injected into the first HTTP request of each local
connection, replacing incoming matching headers. The local HTTP application must
disable keepalive for these channels; WebSocket upgrades remain full duplex.
`start()` is nonblocking and idempotent. `stop()` closes outbound channels and
retry timers; create a new agent object to start again. Status includes the public
`id`, `fingerprint`, `status`, an `error` when applicable, and `url` only when ready.

The gateway is attached to an existing Node HTTP server through `handle(req,res)`
and `upgrade(req,socket,head)`. `handle` returns whether it handled the request.
`close()` releases all gateway connections. Supply a private `dataDir` and an
`isAdmin(req)` authentication callback.

Run `npm ci` and `npm test` for real enrollment/approval, HTTP binary streaming,
WebSocket echo, readiness, credential collision and revocation checks. Migration
coverage uses synthetic user/service identities on the same loopback gateway,
verifies independent approval and grants, and preserves the legacy profile,
record and live transport. Tests do not alter a production controller.

## License

MIT License. Copyright (c) 2026 Anubis-Locker. See [LICENSE](LICENSE) for the
complete terms; retain its copyright and permission notice in copies or
substantial portions of the software.
