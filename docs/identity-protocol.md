# Identity Protocol

The HTTP contract between the connector and Velode Identity. Applications do not call these addresses themselves;
the connector does. It is documented here for reviewers, for alternative clients and to explain what the connector
sends.

## Addresses

The connector is given one address, the organization address from the Identity panel,
`https://identity.example.com/o/{organizationId}`, and asks Identity for the rest once, the first time it needs
it, without a key:

```http
GET https://identity.example.com/o/{organizationId}/.well-known/velode-identity
```

```json
{"success": true, "data": {"organizationId": "…", "loginUrl": "https://identity.example.com/o/…/login",
  "apiUrl": "https://identity.example.com/api/organizations/…"}}
```

| Address | Used by |
| --- | --- |
| `loginUrl` | The browser, for the sign-in page |
| `apiUrl` | The connector, as the base of every call below |

The connector deduces neither. It believes them only when both are on the host of the address it was given and
the document names the same organization, since the connection key and session tokens travel there; otherwise
sign-in answers `503`.

## Requests And Answers

Every call is a `POST` with a JSON body and `Content-Type: application/json`, authenticated by the connection key:

```http
X-Server-Connection-Key: <connection key>
```

Every call except `/connection` also sends `appSlug`, the identifier Identity assigned when it approved the
application.

A success answers `200` with the result in `data`, or `204` without a body:

```json
{"success": true, "data": {"userId": "5b4084b4-8c5c-47a5-a1e2-9d1654a7338b", "email": "user@example.com"}}
```

A failure answers an error status with a code:

```json
{"status": 401, "error": "INVALID_CONNECTION_KEY", "message": "Invalid server connection key"}
```

`401 INVALID_CONNECTION_KEY` means Identity refused the key itself. The connector then reloads the stored connection,
since another replica may have replaced the key, and asks to be approved again if the key is still refused.

## Connection

| Call | Body | Answer |
| --- | --- | --- |
| `/connection` | `origin`, `name`, `key`, `callbackPath`, `invitation`? | `status`: `PENDING` with an approval `code`, or `CONNECTED` with `appSlug`; `403` when an invitation is needed |
| `/connection/rotate` | `newKey` | `204` once the new key replaces the one in the header |

`callbackPath` is `/velode-identity/callback`, the path of the application's origin Identity returns a sign-in to;
the administrator sees it before approving and Identity returns a sign-in to no other address.

`invitation` is 43 characters of unpadded base64url that an administrator creates in the panel for the application's
exact origin. It works once and for one hour. Identity needs it with a key it has not seen and ignores it with one
it knows, whatever was decided about that key; the connector cannot tell which is the case, so it sends the
invitation it was configured with on every `/connection` call. A key Identity has not seen, sent without an
invitation or with one that is wrong, expired, already used or created for another origin, answers `403` without
saying which:

```json
{"status": 403, "error": "CONNECTION_INVITATION_REQUIRED", "message": "A valid connection invitation is required"}
```

The connector then keeps asking and tells the operator in its log to set a new invitation. Repeating a request keeps
it waiting for approval, but for no more than 24 hours after it was made; after that, and after an administrator
disconnects the application or its stored connection is lost, connecting takes a new invitation. An approved
connection and `/connection/rotate` never need one.

The connector calls `/connection` with a new key every ten seconds until an administrator approves it, and replaces the
key with `/connection/rotate` when it is due. It stores the replacement before sending it, so a crash after Identity
accepts it does not lose the connection.

## Redirect Sign-In

1. The connector sends the browser to
   `{loginUrl}?appSlug={appSlug}&returnTo={app-url}/velode-identity/callback&state={state}`. `returnTo` must be the
   application's callback exactly; anything else answers `400` before the user signs in.
2. Identity signs the user in and returns to the callback with `velode_identity_code` and `velode_identity_state`.
3. The connector checks the state and trades the code:

| Call | Body | Answer |
| --- | --- | --- |
| `/session/exchange` | `code` | `userId`, `email`, `sessionToken`, `expiresAt` (ISO-8601) |
| `/verify` | `token` | `userId`, `email` while the session is valid and the user may enter the application |
| `/session/revoke` | `token` | `200` with `signOutUrl` when the session was ended, `204` when there was none to end |

`/session/revoke` makes Identity stop accepting the token at once. `signOutUrl` is on Identity's host and valid
for a minute: the connector sends the browser there, Identity ends the user's own sign-in to the organization and
returns the browser to the application. The connector follows it only when it is on the host it was given.

## Sign-In On The Application's Own Page

| Call | Body | Answer |
| --- | --- | --- |
| `/login-flow/options` | — | `turnstileSiteKey` and `turnstileAction` when Turnstile is required |
| `/login-flow/start` | `email`, `clientAddress`, `turnstileToken`? | `next: EMAIL_CODE`, `flowId`, `flowSecret` |
| `/login-flow/resend` | `flowId`, `flowSecret`, `clientAddress`, `turnstileToken`? | `next: EMAIL_CODE` |
| `/login-flow/email-code` | `flowId`, `flowSecret`, `code`, `clientAddress` | `next: TOTP`, or `next: DONE` with a session |
| `/login-flow/totp` | `flowId`, `flowSecret`, `code`, `clientAddress` | `next: DONE` with a session |

A session is `userId`, `email`, `sessionToken` and `expiresAt`, as in `/session/exchange`. `start` answers
`EMAIL_CODE` whether or not the address has an account. `clientAddress` is the browser's address, to which Identity
applies its limits. Error codes include `INVALID_CODE`, `TURNSTILE_REJECTED`, `VALIDATION_ERROR`, `ACCESS_DENIED`,
`LOCKED` and `RATE_LIMITED`.

## The User's Second Factor

| Call | Body | Answer |
| --- | --- | --- |
| `/account/second-factor` | `token` | `authenticator`, `securityKeys` |
| `/account/authenticator/setup` | `token`, `clientAddress` | `setupId`, `manualKey`, `otpauthUri`, `qrDataUri`, `expiresAt` |
| `/account/authenticator/resend` | `token`, `setupId`, `manualKey` | `authenticator`, `securityKeys` |
| `/account/authenticator/confirm` | `token`, `setupId`, `manualKey`, `emailCode`, `code` | `authenticator`, `securityKeys` |
| `/account/authenticator/disable` | `token`, `code`, `clientAddress` | `authenticator`, `securityKeys` |

`token` is the user's session in this application, checked as `/verify` checks it (`401 INVALID_SESSION`
otherwise). Identity keeps only hashes of a setup's key and mailed code, so the connector keeps the key and sends it
back. Error codes include `INVALID_EMAIL_CODE`, `INVALID_CODE`, `SETUP_EXPIRED`, `ALREADY_ENABLED`, `NOT_ENABLED`,
`LOCKED`, `RATE_LIMITED` and `MAIL_UNAVAILABLE`.

Before handing a `DONE` session to the application, the connector calls `/verify` with its token and accepts it only
when Identity names the same user.
