# Advanced Usage

## Connection Storage

The connector keeps its connection in the application's own storage so every replica shares it: a
`velode_identity_connection` table it creates when the application has a `JdbcTemplate`. Declare a `ConnectionStore`
bean to keep it elsewhere. A custom store must implement atomic `create` and `compareAndSet(expected, updated)`;
a missing or changed expected value returns false. The previous unconditional `save` contract is removed.

Update Identity first, then update all connector replicas together after adapting custom stores. Older connector versions can overwrite newer connection
state. The stored format is unchanged.

If an administrator disconnects the application, or its storage is lost, the connector asks to connect again and the
panel shows the request as a reconnection of the same application. Connecting again takes a new invitation: the
application keeps running and answers `503` to sign-in, and its log says to create one and set
`velode.identity.invitation`. With several replicas, one started with the new invitation is enough, because they
share the key.

## Installing From GitHub Packages

Every release is also published to GitHub Packages. Add the repository under `<repositories>`:

```xml
<repository>
    <id>github-velode</id>
    <url>https://maven.pkg.github.com/velodeworks/Velode-Identity-Connector</url>
</repository>
```

and its credentials under `<servers>` in `~/.m2/settings.xml`, on developer machines and CI:

```xml
<server>
    <id>github-velode</id>
    <username>GITHUB_USERNAME</username>
    <password>${env.GITHUB_PACKAGES_TOKEN}</password>
</server>
```

`GITHUB_PACKAGES_TOKEN` is a GitHub personal access token (classic) with the `read:packages` scope, which GitHub
Packages requires even for public packages. Keep it out of git.

## Configuration

`velode.identity.name` overrides the name suggested to the administrator (default `spring.application.name`) and
`velode.identity.key-rotation` how often the key is replaced (default `30d`).

`velode.identity.invitation` is the one-use invitation an administrator creates in the Identity panel for the
application's address, valid for one hour. The connector sends it while it asks for a connection, and Identity
needs it only for a request it has not seen; a connected application does not use it, so it can be removed then.
It must be the 43 characters the panel shows, or the application does not start. The connector never logs it.

`velode.identity.verification-cache` is how long the connector trusts Identity's confirmation of a session before
asking again (default `5s`, at most `1m`). An application checks its user on every request, and without this each
request would wait for Identity. Within that time a user who signed out in another application, was disabled or lost
access is still let in; `0` asks Identity on every call. Each replica of the application remembers on its own.
A session in use is confirmed again during the last second of that time, away from the request, so a user who keeps
working does not wait for Identity; a confirmation is never trusted for longer than the configured time. A session
Identity refuses is remembered for the same time.

`velode.identity.verification-cache-size` is how many sessions a replica remembers at once (default `100000`, about
a hundred bytes each). When it is full the remembered sessions keep being answered from memory and the others are
asked about on every call, so set it above the number of users at work on one replica.

## Browser Flows

`VelodeIdentity` also offers `loginUrl`, `exchange` and `verify` for applications that manage the browser flow
themselves. `currentUser` and `verify` ask Identity and trust its confirmation for
`velode.identity.verification-cache`, and a refusal for the same time. An application
that signs users out by itself calls `forget(token)` so the sign-out takes effect at once, as the connector's own
sign-out does. Every method that asks Identity throws `IdentityUnavailableException` when Identity cannot be
reached; the connector's own sign-in addresses answer `503` in that case.

## Your Own Sign-In Page

An application can show email sign-in on its own page, with its own design, instead of linking to Identity's page.
Identity still decides every step; the page only collects what the user types and sends it to the connector, which
is the only thing that talks to Identity. Requires Identity with the `login-flow` protocol.

| Request | Body | Success |
| --- | --- | --- |
| `GET /velode-identity/flow/options` | — | `{"turnstileSiteKey", "turnstileAction"}` when Turnstile is required, else `{}` |
| `POST /velode-identity/flow/start` | `{"email", "turnstileToken"?}` | `{"next":"EMAIL_CODE"}` |
| `POST /velode-identity/flow/resend` | `{"turnstileToken"?}` | `{"next":"EMAIL_CODE"}` |
| `POST /velode-identity/flow/code` | `{"code"}` | `{"next":"TOTP"}`, `{"next":"DONE"}` or `{"next":"HOSTED_LOGIN"}` |
| `POST /velode-identity/flow/totp` | `{"code"}` | `{"next":"DONE"}` |

```js
async function step(name, body) {
  const response = await fetch(`/velode-identity/flow/${name}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  return response.json(); // {"next": ...} or {"error": ...}
}
await step("start", { email });             // always EMAIL_CODE, so it never reveals whether an account exists
const { next } = await step("code", { code }); // TOTP asks for the authenticator code next; DONE is signed in
```

The flow lives in an `HttpOnly` cookie that page scripts never see; `DONE` sets the same session cookie as the
redirect sign-in, after Identity confirms the session it issued. `HOSTED_LOGIN` means the account finishes
on Identity's own page, as one whose only second factor is a security key does: send the browser to
`/velode-identity/login`. Requests must be JSON and come from the page's own
origin: a `POST` whose `Origin` differs from `velode.identity.app-url`, or whose `Sec-Fetch-Site` is not
`same-origin`, answers `403` `{"error":"CROSS_ORIGIN"}`. Serve the page from that origin. Failures answer
`{"error": CODE}`: `INVALID_CODE` (wrong, used or expired code: ask again or restart), `TURNSTILE_REJECTED`,
`LOCKED`, `RATE_LIMITED`, `ACCESS_DENIED` (the account may not enter this application), `NO_FLOW` (start first) and
`NOT_CONNECTED` or `IDENTITY_UNAVAILABLE`. With Spring Security, permit `/velode-identity/**` and either exclude
`/velode-identity/flow/**` from CSRF or send the CSRF header with these requests.

When `options` names a site key, render Cloudflare Turnstile with that key and action and send its token with
`start` and `resend`; the application's host must be in the widget's hostnames. Identity applies its limits and
lockouts to the browser's address: behind a proxy, set `server.forward-headers-strategy` so `getRemoteAddr()` is the
browser's. Codes for these sign-ins name the application and have no magic link. OAuth providers still use the
redirect sign-in, and sign-ins on an application's own page are not shared with other applications.
`VelodeIdentity` offers the same steps as `loginOptions`, `startLogin`, `resendLoginCode`, `submitLoginCode` and
`submitAuthenticatorCode` for applications that keep the flow themselves.

## Two-Step Verification In Your Settings

An application can let its signed-in users turn an authenticator app (Google Authenticator, 1Password and the like)
on and off from its own settings page, with its own design. Identity decides every step for the user the session
cookie names; the page only shows what it is given and sends what the user types. Requires Identity with the
`account` protocol, and the Organization needs a mail server: turning the authenticator on also needs a code Identity
mails to the user, because an open session alone does not prove who is at the keyboard.

| Request | Body | Success |
| --- | --- | --- |
| `GET /velode-identity/account/second-factor` | — | `{"authenticator": bool, "securityKeys": bool}` |
| `POST /velode-identity/account/authenticator/setup` | `{}` | `{"manualKey", "otpauthUri", "qrDataUri", "expiresAt"}` |
| `POST /velode-identity/account/authenticator/resend` | `{}` | `{"sent": true}` |
| `POST /velode-identity/account/authenticator/confirm` | `{"emailCode", "code"}` | `{"authenticator": true, ...}` |
| `POST /velode-identity/account/authenticator/disable` | `{"code"}` | `{"authenticator": false, ...}` |

```js
async function account(path, body) {
  const response = await fetch(`/velode-identity/account/${path}`, body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  return response.json(); // the answer or {"error": ...}
}
const setup = await account("authenticator/setup", {});  // show <img src=setup.qrDataUri> and setup.manualKey
await account("authenticator/confirm", { emailCode, code }); // the code from the email and one from the app
```

`setup` mails the user a code and answers the QR code, the key to type by hand and when the setup expires, which is
as long as a sign-in code lasts. The setup itself stays in an `HttpOnly` cookie; starting again replaces it.
`confirm` needs the mailed code and a code the authenticator shows, and five wrong attempts end the setup. `disable`
needs a code the authenticator shows; wrong ones count towards the same lockout as wrong sign-in codes. Security keys
sign only for Identity's own address, so `securityKeys` only says whether the user has any: link to Identity's account
page for them. Requests follow the same rules as the sign-in steps: JSON, from the page's own origin, 8 KB at most.
Failures answer `{"error": CODE}`: `SIGNED_OUT` or `INVALID_SESSION` (`401`), `INVALID_EMAIL_CODE` or `INVALID_CODE`
(`400`: ask again), `SETUP_EXPIRED` (`410`: start again), `NO_SETUP` (`400`: start first), `ALREADY_ENABLED` or
`NOT_ENABLED` (`409`), `LOCKED`, `RATE_LIMITED`, and `MAIL_UNAVAILABLE`, `NOT_CONNECTED` or `IDENTITY_UNAVAILABLE`
(`503`). With Spring Security, exclude `/velode-identity/account/**` from CSRF or send the CSRF header, as for the
sign-in steps. `VelodeIdentity` offers the same steps as `secondFactor`, `startAuthenticatorSetup`,
`resendAuthenticatorCode`, `confirmAuthenticator` and `disableAuthenticator`, each taking the request that carries
the session cookie.
