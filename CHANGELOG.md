# Changelog

## 0.7.0

### Upgrade Notes

- This version needs an Identity that says where an organization is reached. The connector reads it once, from the
  organization address it is given, the first time it needs it; `velode.identity.url` stays as it is. Against an
  older Identity sign-in answers `503`.

### Security

- Identity returns a sign-in only to the application's callback, `/velode-identity/callback` on its address, and
  no longer to any page of that address. The connector declares it when it asks to connect, and the
  administrator sees it before approving. An application connected with an earlier version has it typed once
  in its panel in Identity; until then its sign-in link answers `400`.

### Changed

- The connector no longer deduces Identity's sign-in page and API from the organization address: Identity tells
  them, and is believed only when both are on the host of that address, since the connection key and session
  tokens travel there.

## 0.6.0

### Upgrade Notes

- Connecting an application needs a connection invitation and this version. An administrator creates the invitation
  for the application's address in the Identity panel, and the application sets it as `velode.identity.invitation`
  before it starts. It works once and for one hour, and can be removed once the application is connected.
- Applications that are already connected are unaffected and need no invitation; their keys are replaced as before.
- Connecting again, after an administrator disconnects the application or its stored connection is lost, needs a
  new invitation. Until it has one the application keeps running, answers `503` to sign-in and says in its log what
  to do.
- Signing out is now a `POST`. A link to `/velode-identity/logout` answers `405`; replace it with a form:
  `<form method="post" action="/velode-identity/logout"><button type="submit">Sign out</button></form>`.
  An application with Spring Security's CSRF protection on sends its CSRF token with that form or excludes
  `/velode-identity/logout`, as it does for `/velode-identity/flow/**`.
- A sign-out that carries neither an `Origin` nor a `Sec-Fetch-Site` header is refused with `403`. Browsers send
  them with a form, but a page served with `Referrer-Policy: no-referrer` sends `Origin: null` on its forms and is
  refused.

### Security

- Identity registers a connector's request only with an administrator's invitation, so a stranger who knows an
  organization's address can no longer fill its list of requests and keep other applications from connecting.
- Another site can no longer sign a user out with a link, which worked in browsers that do not send
  `Sec-Fetch-Site`.
- The connector reads at most 64 KB of an answer from Identity, whose answers stay under 2 KB, so a faulty or
  hostile proxy in front of Identity cannot make every application hold a large body in memory. A longer answer
  throws `IdentityUnavailableException`, like an answer that never came.

## 0.5.0

### Upgrade Notes

- `currentUser` and `verify` no longer ask Identity on every call. A session Identity confirmed is trusted for five
  seconds, so an application that checks its user on every request waits for Identity once in that time instead of
  each time. A user who signs out elsewhere, is disabled or loses access is refused within those five seconds
  instead of on the next request. Set `velode.identity.verification-cache=0` to keep asking every time, or up to
  `1m` to ask less often.
- `VelodeIdentity.forget(token)` stops trusting an earlier confirmation. Applications that sign users out by
  themselves call it; the connector's own sign-out does.
- A session in use is confirmed again shortly before those five seconds end, away from the request, so a user who
  keeps working never waits for Identity. The time a confirmation is trusted does not grow: each one counts from
  the moment Identity gave it.
- A session Identity refuses is remembered for the same time, so a stale cookie costs one call and not one per
  request. A user who signs in again is recognised at once.
- Requests that verify the same session at the same moment wait for one call to Identity, and the page a user
  lands on after signing in does not ask again.
- `velode.identity.verification-cache-size` (default `100000`) is how many sessions one replica remembers. Beyond
  it, the remembered sessions keep being answered and the rest are asked about every time; the memory was emptied
  at 10 000 sessions before.
- An approved connection is read from its store once a minute instead of every ten seconds.

## 0.4.1

- `IdentityUnavailableException` is now a public class applications can catch; previously it was nested in an internal
  class. Code that caught `RuntimeException` keeps working.
- The sign-in callback answers `503` instead of an error page when Identity cannot be reached.
- The jar carries `LICENSE` and `NOTICE`, and declares the module name `com.velode.identity.connector`.
- Published to Maven Central, signed with the Velode release key; no repository or token needed to install.
- Releases include sources and Javadoc.

## 0.4.0

First public release, licensed under Apache 2.0.

### Upgrade Notes

- `velode.identity.url` and `velode.identity.app-url` must use `https`; plain `http` is accepted only for
  `localhost`, `127.0.0.1` and `[::1]`. `app-url` must be a bare origin, without a path, query or credentials.
  The application does not start otherwise.
- The JSON sign-in steps refuse requests from another origin with `403 {"error":"CROSS_ORIGIN"}`. Serve the
  application's sign-in page from the origin in `velode.identity.app-url`.

### Security

- Sign-out started by another site is refused.
- The Identity client never follows redirects.
- Incomplete or malformed answers from Identity fail the sign-in instead of raising errors; a corrupted state
  cookie returns the user home.
- Connector responses are not cached, JSON is marked `nosniff` and the callback sends no referrer.
- Spring Boot 3.5.16 clears the advisories reported against 3.5.14's managed dependencies.

## 0.3.0

- Applications can host their own email sign-in page through `/velode-identity/flow/*`.

## 0.2.0

- Sends the `X-Server-Connection-Key` header Identity expects.
- Key rotation is safe across replicas; custom `ConnectionStore`s implement atomic `create` and `compareAndSet`.

## 0.1.0

- First version of the starter.
