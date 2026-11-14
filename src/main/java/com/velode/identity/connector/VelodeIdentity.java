package com.velode.identity.connector;

import com.velode.identity.connector.ConnectionManager.Connection;
import com.velode.identity.connector.IdentityClient.Response;
import com.velode.identity.connector.VerifiedSessions.Remembered;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;

/**
 * What a connected application asks Identity: where to send a user to sign in and who a session belongs to.
 * Identity only says who the user is and that they may enter this application; the application decides the rest.
 * Every method that asks Identity throws {@link IdentityUnavailableException} when Identity cannot be reached.
 */
public class VelodeIdentity {

    /** Cookie in which the connector's web endpoints keep the user's application session token. */
    public static final String SESSION_COOKIE = "velode_identity_session_token";

    static final String CALLBACK_PATH = "/velode-identity/callback";

    private final VelodeIdentityProperties properties;
    private final ConnectionManager connections;
    private final IdentityClient client;
    private final VerifiedSessions verified;
    /** The sessions Identity is being asked about right now, so that each is asked about once at a time. */
    private final Map<String, CompletableFuture<Optional<IdentityUser>>> asking = new ConcurrentHashMap<>();
    private final Executor renewals;

    VelodeIdentity(VelodeIdentityProperties properties, ConnectionManager connections, IdentityClient client) {
        this(properties, connections, client, System::nanoTime, Executors.newVirtualThreadPerTaskExecutor());
    }

    /**
     * @param nanoTime a clock that only moves forward
     * @param renewals runs the calls that confirm again a session in use, away from the request that noticed
     */
    VelodeIdentity(
        VelodeIdentityProperties properties, ConnectionManager connections, IdentityClient client, LongSupplier nanoTime,
        Executor renewals
    ) {
        this.properties = properties;
        this.connections = connections;
        this.client = client;
        this.verified = new VerifiedSessions(properties.verificationCache(), properties.verificationCacheSize(), nanoTime);
        this.renewals = renewals;
    }

    /** False until an administrator approves this application in the Identity panel. */
    public boolean isConnected() {
        return connections.connected().isPresent();
    }

    /** Identity's sign-in page; it returns the user to this application's callback with a one-time code. */
    public Optional<String> loginUrl(String state) {
        return connections.connected().map(connection -> properties.url() + "/login"
            + "?appSlug=" + encode(connection.appSlug())
            + "&returnTo=" + encode(properties.appUrl() + CALLBACK_PATH)
            + "&state=" + encode(state));
    }

    /** Trades the one-time code Identity appended to the callback for the user's session. */
    public Optional<IdentitySession> exchange(String code) {
        Optional<IdentitySession> session = call("/session/exchange", "code", code).flatMap(VelodeIdentity::session);
        // Identity has just said whose session this is, so the page the user lands on does not ask again.
        session.ifPresent(issued -> verified.confirm(VerifiedSessions.key(issued.token()), issued.user()));
        return session;
    }

    /**
     * The user a session token belongs to, while it is valid and the user may still enter this application.
     * What Identity says is trusted for {@code velode.identity.verification-cache} (five seconds unless
     * configured), so a user who signs out elsewhere or loses access is refused within that time, and so is a
     * session Identity refused. A session in use is confirmed again shortly before that time ends, away from the
     * request, so a user who keeps working does not wait for Identity; requests that need the same answer at the
     * same moment wait for one call.
     */
    public Optional<IdentityUser> verify(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        if (!verified.remembers()) {
            return ask(token);
        }
        String key = VerifiedSessions.key(token);
        Remembered remembered = verified.find(key);
        if (remembered == null) {
            return askOnce(key, token);
        }
        if (remembered.dueForRenewal()) {
            renew(key, token);
        }
        return Optional.ofNullable(remembered.user());
    }

    /**
     * Stops trusting what Identity said about this token, so the next {@link #verify(String)} asks Identity.
     * Call it when the application signs the user out by itself; the connector's own sign-out does.
     */
    public void forget(String token) {
        if (token != null) {
            verified.forget(VerifiedSessions.key(token));
        }
    }

    /** Asks Identity, or waits for the answer when another request is already asking about the same session. */
    private Optional<IdentityUser> askOnce(String key, String token) {
        CompletableFuture<Optional<IdentityUser>> mine = new CompletableFuture<>();
        CompletableFuture<Optional<IdentityUser>> first = asking.putIfAbsent(key, mine);
        if (first != null) {
            try {
                return first.join();
            } catch (CompletionException exception) {
                if (exception.getCause() instanceof RuntimeException failure) {
                    throw failure;
                }
                throw exception;
            }
        }
        try {
            Optional<IdentityUser> said = askAndRemember(key, token);
            mine.complete(said);
            return said;
        } catch (RuntimeException failure) {
            mine.completeExceptionally(failure);
            throw failure;
        } finally {
            asking.remove(key, mine);
        }
    }

    /** Confirms again a session in use while its last confirmation still stands; nobody waits for it. */
    private void renew(String key, String token) {
        CompletableFuture<Optional<IdentityUser>> mine = new CompletableFuture<>();
        if (asking.putIfAbsent(key, mine) != null) {
            return;
        }
        try {
            renewals.execute(() -> {
                try {
                    mine.complete(askAndRemember(key, token));
                } catch (RuntimeException failure) {
                    // Identity could not be asked: the last confirmation stands until its time ends.
                    mine.completeExceptionally(failure);
                } finally {
                    asking.remove(key, mine);
                }
            });
        } catch (RuntimeException rejected) {
            asking.remove(key, mine);
            mine.completeExceptionally(rejected);
        }
    }

    /**
     * Remembers a confirmation and a refusal. Nothing is remembered when Identity was not asked, because this
     * application is not connected, or did not answer about the session, because it is busy or failing.
     */
    private Optional<IdentityUser> askAndRemember(String key, String token) {
        Optional<Response> answered = send("/verify", Map.of("token", token));
        Optional<IdentityUser> user = answered.filter(response -> response.status() == 200).flatMap(VelodeIdentity::user);
        if (user.isPresent()) {
            verified.confirm(key, user.get());
        } else if (answered.isPresent() && answered.get().status() == 401) {
            verified.refuse(key);
        }
        return user;
    }

    /** What Identity says about the token right now. */
    private Optional<IdentityUser> ask(String token) {
        return call("/verify", "token", token).flatMap(VelodeIdentity::user);
    }

    /** The user signed in through the connector's web endpoints, as {@link #verify(String)} confirms them. */
    public Optional<IdentityUser> currentUser(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (SESSION_COOKIE.equals(cookie.getName())) {
                return verify(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    /** What this application's own sign-in page must render before {@link #startLogin}; empty until connected. */
    public Optional<LoginOptions> loginOptions() {
        return send("/login-flow/options", Map.of()).filter(response -> response.status() == 200)
            .map(response -> new LoginOptions(response.text("turnstileSiteKey"), response.text("turnstileAction")));
    }

    /**
     * Starts email sign-in on this application's own page. Identity answers {@code EMAIL_CODE} whether or not the
     * address has an account, and emails a code only when it may sign in.
     *
     * @param clientAddress IP address of the browser this request serves
     * @param turnstileToken token solved on this page when {@link #loginOptions()} names a site key, otherwise null
     */
    public LoginStep startLogin(String email, String clientAddress, String turnstileToken) {
        return loginStep("/login-flow/start", null, fields(
            "email", email, "clientAddress", clientAddress, "turnstileToken", turnstileToken));
    }

    /** Emails a fresh code for a started flow; Identity applies its cooldown and resend limit. */
    public LoginStep resendLoginCode(LoginFlow flow, String clientAddress, String turnstileToken) {
        return loginStep("/login-flow/resend", flow, fields(
            "clientAddress", clientAddress, "turnstileToken", turnstileToken));
    }

    /** Submits the emailed code; answers {@code TOTP} when the account has a second factor, otherwise {@code DONE}. */
    public LoginStep submitLoginCode(LoginFlow flow, String code, String clientAddress) {
        return loginStep("/login-flow/email-code", flow, fields("code", code, "clientAddress", clientAddress));
    }

    /** Submits the authenticator code of an account with a second factor. */
    public LoginStep submitAuthenticatorCode(LoginFlow flow, String code, String clientAddress) {
        return loginStep("/login-flow/totp", flow, fields("code", code, "clientAddress", clientAddress));
    }

    private LoginStep loginStep(String path, LoginFlow flow, Map<String, String> fields) {
        if (flow != null) {
            fields.put("flowId", flow.id().toString());
            fields.put("flowSecret", flow.secret());
        }
        Optional<Response> sent = send(path, fields);
        if (sent.isEmpty()) {
            return LoginStep.failed(LoginStep.NOT_CONNECTED);
        }
        Response response = sent.get();
        if (response.status() != 200) {
            return LoginStep.failed(response.text("error") == null ? LoginStep.LOGIN_FAILED : response.text("error"));
        }
        Optional<LoginStep> step = switch (String.valueOf(response.text("next"))) {
            case "EMAIL_CODE" -> continued(response, flow)
                .map(next -> new LoginStep(LoginStep.Next.EMAIL_CODE, next, null, null));
            case "TOTP" -> Optional.ofNullable(flow).map(next -> new LoginStep(LoginStep.Next.TOTP, next, null, null));
            case "DONE" -> session(response).map(this::confirmed);
            default -> Optional.empty();
        };
        return step.orElseGet(() -> LoginStep.failed(LoginStep.LOGIN_FAILED));
    }

    /** The flow Identity started, or the one in progress when it did not name a new one. */
    private static Optional<LoginFlow> continued(Response response, LoginFlow flow) {
        String id = response.text("flowId");
        String secret = response.text("flowSecret");
        if (id == null) {
            return Optional.ofNullable(flow);
        }
        try {
            return secret == null ? Optional.empty() : Optional.of(new LoginFlow(UUID.fromString(id), secret));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /** A session is handed to the application only after Identity confirms its token belongs to the same user. */
    private LoginStep confirmed(IdentitySession session) {
        if (ask(session.token()).filter(user -> user.userId().equals(session.user().userId())).isEmpty()) {
            return LoginStep.failed(LoginStep.LOGIN_FAILED);
        }
        verified.confirm(VerifiedSessions.key(session.token()), session.user());
        return new LoginStep(LoginStep.Next.DONE, null, session, null);
    }

    private static Map<String, String> fields(String... namesAndValues) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (int index = 0; index < namesAndValues.length; index += 2) {
            if (namesAndValues[index + 1] != null) {
                fields.put(namesAndValues[index], namesAndValues[index + 1]);
            }
        }
        return fields;
    }

    private Optional<Response> call(String path, String field, String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return send(path, Map.of(field, value)).filter(response -> response.status() == 200);
    }

    /** Identity's answer, or empty while this application is not connected. */
    private Optional<Response> send(String path, Map<String, String> fields) {
        // A refused key is retried once: another replica may have replaced it, or it was replaced before a crash.
        for (int attempt = 0; attempt < 2; attempt++) {
            Optional<Connection> connection = connections.connected();
            if (connection.isEmpty()) {
                return Optional.empty();
            }
            Map<String, String> body = new LinkedHashMap<>();
            body.put("appSlug", connection.get().appSlug());
            body.putAll(fields);
            Response response = client.post(path, connection.get().key(), body);
            if (!response.keyRefused()) {
                return Optional.of(response);
            }
            connections.recover(connection.get());
        }
        return Optional.empty();
    }

    /** An answer without a usable user identifier proves nobody's identity. */
    private static Optional<IdentityUser> user(Response response) {
        String userId = response.text("userId");
        try {
            return userId == null ? Optional.empty()
                : Optional.of(new IdentityUser(UUID.fromString(userId), response.text("email")));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /** The session Identity issued, or empty when its answer lacks the user, the token or a valid expiry. */
    private static Optional<IdentitySession> session(Response response) {
        String token = response.text("sessionToken");
        String expiresAt = response.text("expiresAt");
        if (token == null || expiresAt == null) {
            return Optional.empty();
        }
        try {
            Instant expiry = Instant.parse(expiresAt);
            return user(response).map(user -> new IdentitySession(user, token, expiry));
        } catch (DateTimeParseException exception) {
            return Optional.empty();
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * A user Identity authenticated and admits to this application.
     *
     * @param userId immutable identifier to own the user's data with
     * @param email the user's primary email in the organization
     */
    public record IdentityUser(UUID userId, String email) {
    }

    /**
     * What this application's own sign-in page renders before starting email sign-in.
     *
     * @param turnstileSiteKey Cloudflare Turnstile site key the start requires, or null when it requires none
     * @param turnstileAction action the Turnstile widget must declare, or null
     */
    public record LoginOptions(String turnstileSiteKey, String turnstileAction) {
    }

    /**
     * One email sign-in in progress. Keep it server-side, such as in an HttpOnly cookie; it continues the sign-in.
     */
    public record LoginFlow(UUID id, String secret) {

        @Override
        public String toString() {
            return "LoginFlow[id=" + id + "]";
        }
    }

    /**
     * What Identity decided for one sign-in step: the next step, or the error that stopped this one.
     *
     * @param flow the flow to continue, until {@code DONE}
     * @param session the user's session in this application, once {@code DONE}
     * @param error Identity's error code, such as {@code INVALID_CODE}, {@code LOCKED} or {@code RATE_LIMITED}
     */
    public record LoginStep(Next next, LoginFlow flow, IdentitySession session, String error) {

        /** This application is not connected yet, so Identity cannot be asked. */
        public static final String NOT_CONNECTED = "NOT_CONNECTED";

        /** Identity gave no usable answer, or did not confirm the session it issued. */
        public static final String LOGIN_FAILED = "LOGIN_FAILED";

        static LoginStep failed(String error) {
            return new LoginStep(null, null, null, error);
        }

        public boolean failed() {
            return error != null;
        }

        /** The next thing the user does on this application's sign-in page. */
        public enum Next {
            EMAIL_CODE,
            TOTP,
            DONE
        }
    }

    /**
     * A user's session in this application.
     *
     * @param token opaque value to keep server-side or in an HttpOnly cookie and pass to {@link #verify(String)}
     */
    public record IdentitySession(IdentityUser user, String token, Instant expiresAt) {

        @Override
        public String toString() {
            return "IdentitySession[user=" + user + "]";
        }
    }
}
