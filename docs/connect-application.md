# Connect An Application

This guide connects a Java 21, Spring Boot 3.5 or 4.x servlet application to Velode Identity.
The application needs a public HTTPS origin and must reach Identity over HTTPS.

## 1. Prepare The Organization

A global administrator opens the organization's panel in Identity, confirms it is active, and adds the app's
domain under **Settings > General > Application domains**. The organization needs working authentication and
a user who can sign in. Global and organization sign-ins are separate.

Open **Connect app** and copy the organization address for step 3. In the same panel, create a connection
invitation for the application's address, such as `https://app.example.com`, and copy it too. The invitation is
shown once, works once and is valid for one hour, so create it when the application is ready to start.

## 2. Add The Connector

The connector is published to Maven Central. Add it under `<dependencies>` in the application's `pom.xml`:

```xml
<dependency>
    <groupId>com.velode</groupId>
    <artifactId>identity-spring-boot-starter</artifactId>
    <version>0.7.0</version>
</dependency>
```

Releases are signed with the Velode release key `0FA0 15BF 1377 5E58 2A58 C41E DC3A 6A2D 31C6 A2F1`, published on
`keyserver.ubuntu.com` and `keys.openpgp.org`. The same versions are also on GitHub Packages, which needs a token
even for public packages; see [installing from GitHub Packages](advanced-usage.md#installing-from-github-packages).

## 3. Configure The Application

Set these in the application's `application.properties`, using the address and the invitation copied from
Identity:

```properties
velode.identity.url=https://identity.example.com/o/ORGANIZATION_ID
velode.identity.app-url=https://app.example.com
velode.identity.invitation=INVITATION_FROM_THE_PANEL
```

The app URL is an origin, without a path, on an allowed application domain, and the address the invitation was
created for.
The invitation only lets the application ask to connect, once. It is not the connection key, which the connector
makes by itself, and it is no longer needed once the application is connected. Until then keep it out of git, for
example by setting the environment variable `VELODE_IDENTITY_INVITATION` instead.
Both addresses must use `https`, because the connection key and users' session tokens travel to them; the
connector refuses to start otherwise. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `[::1]`,
for local development.
Use the application's existing `JdbcTemplate` bean and database: the connector creates
`velode_identity_connection` there, so its account needs permission to create that table.
All replicas must share this storage. For another storage option, see [connection storage](advanced-usage.md#connection-storage).

## 4. Allow The Connector Routes

If the app uses Spring Security, permit `/velode-identity/**` in its existing authorization rules,
before broader matchers:

```java
.requestMatchers("/velode-identity/**", "/me").permitAll()
```

The example also permits `/me`, whose handler below checks the user itself. The connector does not populate
Spring Security's `SecurityContext`. Protect other application routes using the
verified user returned in step 6 and the app's own authorization rules.

## 5. Start And Approve

Start the application while the invitation is valid. Its log shows a waiting message with a code, such as
`4F7-A92`. In the organization's **Connect app** panel, compare that code and the app's origin, then approve.
If the log says instead that Identity needs an invitation, or did not accept the one it was given, create a new
one for the application's address, set it and start the application again.

Choose **All users of the organization**, or **Only the people I choose** and add the intended users to the app's
access list. The connector notices approval within ten seconds. No restart or manual connection key is needed.
A request waits for approval while the application keeps running, for 24 hours at most; after that, asking again
takes a new invitation.

Once the log says the application is connected, remove `velode.identity.invitation`: it has been used, and a
connected application does not need one.

## 6. Sign In And Read The User

Add a sign-in link to the application:

```html
<a href="/velode-identity/login?returnTo=/">Sign in</a>
```

Constructor-inject `com.velode.identity.connector.VelodeIdentity` into a Spring MVC controller.
For example, this handler returns the verified user or `401`:

```java
@GetMapping("/me")
ResponseEntity<VelodeIdentity.IdentityUser> me(HttpServletRequest request) {
    return identity.currentUser(request)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.status(401).build());
}
```

Here `identity` is the injected connector; use Spring MVC's `GetMapping`, Spring's `ResponseEntity` and
Jakarta's `HttpServletRequest`. Check the user on every request: the connector asks Identity and trusts its answer
for five seconds, so a busy page does not wait for Identity each time.
Use `userId` to own application data and keep roles and permissions in the app.
When Identity cannot be reached, `currentUser` throws `IdentityUnavailableException`; answer `503` so the user can
try again, rather than treating them as signed out.

Test the sign-in link over HTTPS, then request `/me` in the same browser.
The connector handles the callback and keeps the session in an `HttpOnly`, `Secure` cookie.
Before approval, sign-in returns `503`.

To sign out, post a form to `/velode-identity/logout`:

```html
<form method="post" action="/velode-identity/logout">
    <button type="submit">Sign out</button>
</form>
```

It ends the session everywhere: Identity stops accepting the token at once, the app's cookie is cleared and the
browser passes by Identity, which ends the user's sign-in to the organization and returns them to the application
(its home, or the page set for it in the Identity panel). The next sign-in asks for credentials again. If
Identity cannot be reached the user is still signed out of the app. A link to that address answers `405`, and a
form posted by another site is refused with `403`, so other sites cannot sign users out. If the app keeps
Spring Security's CSRF protection on, send its CSRF token with the form or exclude `/velode-identity/logout`;
see the [security guide](security.md#what-the-application-must-do).

For a custom email sign-in page, see [Your own sign-in page](advanced-usage.md#your-own-sign-in-page). To let users
turn on an authenticator app from the application's settings, see
[Two-step verification in your settings](advanced-usage.md#two-step-verification-in-your-settings).
Before going to production, review the [security guide](security.md) and its checklist.
