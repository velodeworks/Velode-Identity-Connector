package com.velode.identity.connector;

import com.velode.identity.connector.VelodeIdentity.AccountStep;
import com.velode.identity.connector.VelodeIdentity.AuthenticatorSetup;
import com.velode.identity.connector.VelodeIdentity.IdentitySession;
import com.velode.identity.connector.VelodeIdentity.LoginFlow;
import com.velode.identity.connector.VelodeIdentity.LoginOptions;
import com.velode.identity.connector.VelodeIdentity.LoginStep;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.boot.json.JsonParseException;

/**
 * Serves the application's sign-in, callback and sign-out addresses so it only has to link to the first and post a
 * form to the last, and the JSON steps of its own sign-in page.
 */
class VelodeIdentityFilter extends HttpFilter {

    static final String LOGIN_PATH = "/velode-identity/login";
    static final String LOGOUT_PATH = "/velode-identity/logout";

    private static final long serialVersionUID = 1L;
    private static final String CODE_PARAMETER = "velode_identity_code";
    private static final String STATE_PARAMETER = "velode_identity_state";
    private static final String RETURN_PARAMETER = "returnTo";
    private static final String STATE_COOKIE = "velode_identity_state";
    private static final Duration STATE_TTL = Duration.ofMinutes(10);
    private static final String HOME = "/";
    private static final String FLOW_PATH = "/velode-identity/flow/";
    private static final Set<String> FLOW_STEPS = Set.of("options", "start", "resend", "code", "totp");
    private static final String FLOW_COOKIE = "velode_identity_flow";
    private static final Duration FLOW_TTL = Duration.ofMinutes(20);
    private static final String ACCOUNT_PATH = "/velode-identity/account/";
    private static final String SECOND_FACTOR_STEP = "second-factor";
    private static final Set<String> ACCOUNT_STEPS = Set.of(SECOND_FACTOR_STEP, "authenticator/setup",
        "authenticator/resend", "authenticator/confirm", "authenticator/disable");
    private static final String SETUP_COOKIE = "velode_identity_authenticator_setup";
    private static final int MAX_BODY_BYTES = 8192;
    private static final int LOCKED = 423;
    private static final int TOO_MANY_REQUESTS = 429;

    private final transient VelodeIdentity identity;
    private final String appOrigin;
    private final transient SecureRandom random;

    VelodeIdentityFilter(VelodeIdentity identity, String appOrigin, SecureRandom random) {
        this.identity = identity;
        this.appOrigin = appOrigin;
        this.random = random;
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        switch (path) {
            case LOGIN_PATH -> login(request, response);
            case VelodeIdentity.CALLBACK_PATH -> callback(request, response);
            case LOGOUT_PATH -> logout(request, response);
            default -> {
                if (path.startsWith(FLOW_PATH)) {
                    flow(path.substring(FLOW_PATH.length()), request, response);
                } else if (path.startsWith(ACCOUNT_PATH)) {
                    account(path.substring(ACCOUNT_PATH.length()), request, response);
                } else {
                    chain.doFilter(request, response);
                }
            }
        }
    }

    /**
     * JSON steps for the application's own sign-in page. Identity decides every step; the flow stays in an HttpOnly
     * cookie the page's scripts never read. JSON bodies and the origin check keep other sites from starting or
     * continuing a flow.
     */
    private void flow(String step, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        boolean post = "POST".equals(request.getMethod());
        if (!FLOW_STEPS.contains(step)) {
            json(response, HttpServletResponse.SC_NOT_FOUND, Map.of("error", "NOT_FOUND"));
            return;
        }
        // Options is read with GET; every other step is a POST.
        if ("options".equals(step) == post) {
            json(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, Map.of("error", "METHOD_NOT_ALLOWED"));
            return;
        }
        if (post && (request.getContentType() == null
            || !request.getContentType().toLowerCase(Locale.ROOT).startsWith("application/json"))) {
            json(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, Map.of("error", "JSON_REQUIRED"));
            return;
        }
        if (post && !sameOrigin(request, false)) {
            json(response, HttpServletResponse.SC_FORBIDDEN, Map.of("error", "CROSS_ORIGIN"));
            return;
        }
        Map<String, Object> body = post ? body(request) : Map.of();
        if (body == null) {
            json(response, HttpServletResponse.SC_BAD_REQUEST, Map.of("error", "INVALID_REQUEST"));
            return;
        }
        try {
            if ("options".equals(step)) {
                options(response);
                return;
            }
            String client = request.getRemoteAddr();
            Optional<LoginFlow> flow = flowCookie(request);
            if (!"start".equals(step) && flow.isEmpty()) {
                json(response, HttpServletResponse.SC_BAD_REQUEST, Map.of("error", "NO_FLOW"));
                return;
            }
            LoginStep result = switch (step) {
                case "start" -> identity.startLogin(text(body, "email"), client, text(body, "turnstileToken"));
                case "resend" -> identity.resendLoginCode(flow.get(), client, text(body, "turnstileToken"));
                case "code" -> identity.submitLoginCode(flow.get(), text(body, "code"), client);
                default -> identity.submitAuthenticatorCode(flow.get(), text(body, "code"), client);
            };
            respond(result, request, response);
        } catch (IdentityUnavailableException exception) {
            json(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, Map.of("error", "IDENTITY_UNAVAILABLE"));
        }
    }

    /**
     * JSON steps on the signed-in user's second factor, for the application's own settings page. The user is the one
     * the session cookie names; a setup in progress stays in an HttpOnly cookie the page's scripts never read, so the
     * page only shows its QR code and key. The same checks as the sign-in steps keep other sites out.
     */
    private void account(String step, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        boolean post = "POST".equals(request.getMethod());
        if (!ACCOUNT_STEPS.contains(step)) {
            json(response, HttpServletResponse.SC_NOT_FOUND, Map.of("error", "NOT_FOUND"));
            return;
        }
        // The second factors are read with GET; every change is a POST.
        if (SECOND_FACTOR_STEP.equals(step) == post) {
            json(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, Map.of("error", "METHOD_NOT_ALLOWED"));
            return;
        }
        if (post && (request.getContentType() == null
            || !request.getContentType().toLowerCase(Locale.ROOT).startsWith("application/json"))) {
            json(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, Map.of("error", "JSON_REQUIRED"));
            return;
        }
        if (post && !sameOrigin(request, false)) {
            json(response, HttpServletResponse.SC_FORBIDDEN, Map.of("error", "CROSS_ORIGIN"));
            return;
        }
        Map<String, Object> body = post ? body(request) : Map.of();
        if (body == null) {
            json(response, HttpServletResponse.SC_BAD_REQUEST, Map.of("error", "INVALID_REQUEST"));
            return;
        }
        Optional<AuthenticatorSetup> setup = setupCookie(request);
        if (("authenticator/resend".equals(step) || "authenticator/confirm".equals(step)) && setup.isEmpty()) {
            json(response, HttpServletResponse.SC_BAD_REQUEST, Map.of("error", "NO_SETUP"));
            return;
        }
        try {
            String client = request.getRemoteAddr();
            AccountStep result = switch (step) {
                case SECOND_FACTOR_STEP -> identity.secondFactor(request);
                case "authenticator/setup" -> identity.startAuthenticatorSetup(request, client);
                case "authenticator/resend" -> identity.resendAuthenticatorCode(request, setup.get());
                case "authenticator/confirm" -> identity.confirmAuthenticator(
                    request, setup.get(), text(body, "emailCode"), text(body, "code"));
                default -> identity.disableAuthenticator(request, text(body, "code"), client);
            };
            respond(step, result, request, response);
        } catch (IdentityUnavailableException exception) {
            json(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, Map.of("error", "IDENTITY_UNAVAILABLE"));
        }
    }

    private void respond(String step, AccountStep result, HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        if (result.failed()) {
            if ("SETUP_EXPIRED".equals(result.error())) {
                response.addCookie(cookie(SETUP_COOKIE, "", Duration.ZERO, request));
            }
            json(response, accountStatus(result.error()), Map.of("error", result.error()));
            return;
        }
        if (result.setup() != null) {
            AuthenticatorSetup setup = result.setup();
            response.addCookie(cookie(SETUP_COOKIE, setup.id() + "." + setup.manualKey(),
                Duration.between(Instant.now(), setup.expiresAt()), request));
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("manualKey", setup.manualKey());
            fields.put("otpauthUri", setup.otpauthUri());
            fields.put("qrDataUri", setup.qrDataUri());
            fields.put("expiresAt", setup.expiresAt().toString());
            json(response, HttpServletResponse.SC_OK, fields);
            return;
        }
        if ("authenticator/resend".equals(step)) {
            json(response, HttpServletResponse.SC_OK, Map.of("sent", true));
            return;
        }
        if ("authenticator/confirm".equals(step)) {
            response.addCookie(cookie(SETUP_COOKIE, "", Duration.ZERO, request));
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("authenticator", result.secondFactor().authenticator());
        fields.put("securityKeys", result.secondFactor().securityKeys());
        json(response, HttpServletResponse.SC_OK, fields);
    }

    private static int accountStatus(String error) {
        return switch (error) {
            case AccountStep.SIGNED_OUT, "INVALID_SESSION" -> HttpServletResponse.SC_UNAUTHORIZED;
            case "INVALID_CODE", "INVALID_EMAIL_CODE", "VALIDATION_ERROR" -> HttpServletResponse.SC_BAD_REQUEST;
            case "ALREADY_ENABLED", "NOT_ENABLED" -> HttpServletResponse.SC_CONFLICT;
            case "SETUP_EXPIRED" -> HttpServletResponse.SC_GONE;
            case "LOCKED" -> LOCKED;
            case "RATE_LIMITED" -> TOO_MANY_REQUESTS;
            default -> HttpServletResponse.SC_SERVICE_UNAVAILABLE;
        };
    }

    private static Optional<AuthenticatorSetup> setupCookie(HttpServletRequest request) {
        String[] parts = cookieValue(request, SETUP_COOKIE).split("\\.", 2);
        try {
            return parts.length == 2
                ? Optional.of(new AuthenticatorSetup(UUID.fromString(parts[0]), parts[1], null, null, null))
                : Optional.empty();
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private void options(HttpServletResponse response) throws IOException {
        Optional<LoginOptions> options = identity.loginOptions();
        if (options.isEmpty()) {
            json(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, Map.of("error", LoginStep.NOT_CONNECTED));
            return;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        if (options.get().turnstileSiteKey() != null) {
            fields.put("turnstileSiteKey", options.get().turnstileSiteKey());
            fields.put("turnstileAction", options.get().turnstileAction());
        }
        json(response, HttpServletResponse.SC_OK, fields);
    }

    private void respond(LoginStep step, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (step.failed()) {
            json(response, status(step.error()), Map.of("error", step.error()));
            return;
        }
        if (step.next() == LoginStep.Next.HOSTED_LOGIN) {
            // The sign-in continues on Identity's page, so this flow is over.
            response.addCookie(cookie(FLOW_COOKIE, "", Duration.ZERO, request));
        } else if (step.next() == LoginStep.Next.DONE) {
            Duration lifetime = Duration.between(Instant.now(), step.session().expiresAt());
            response.addCookie(cookie(VelodeIdentity.SESSION_COOKIE, step.session().token(), lifetime, request));
            response.addCookie(cookie(FLOW_COOKIE, "", Duration.ZERO, request));
        } else {
            response.addCookie(cookie(FLOW_COOKIE, step.flow().id() + "." + step.flow().secret(), FLOW_TTL, request));
        }
        json(response, HttpServletResponse.SC_OK, Map.of("next", step.next().name()));
    }

    private static int status(String error) {
        return switch (error) {
            case "INVALID_CODE", "TURNSTILE_REJECTED", "VALIDATION_ERROR" -> HttpServletResponse.SC_BAD_REQUEST;
            case "ACCESS_DENIED" -> HttpServletResponse.SC_FORBIDDEN;
            case "LOCKED" -> LOCKED;
            case "RATE_LIMITED" -> TOO_MANY_REQUESTS;
            default -> HttpServletResponse.SC_SERVICE_UNAVAILABLE;
        };
    }

    private static Optional<LoginFlow> flowCookie(HttpServletRequest request) {
        String[] parts = cookieValue(request, FLOW_COOKIE).split("\\.", 2);
        try {
            return parts.length == 2 ? Optional.of(new LoginFlow(UUID.fromString(parts[0]), parts[1])) : Optional.empty();
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /** A small JSON object, or null when the body is too large or not one. */
    private static Map<String, Object> body(HttpServletRequest request) throws IOException {
        byte[] bytes = request.getInputStream().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            return null;
        }
        String text = new String(bytes, StandardCharsets.UTF_8);
        if (text.isBlank()) {
            return Map.of();
        }
        try {
            return new BasicJsonParser().parseMap(text);
        } catch (JsonParseException exception) {
            return null;
        }
    }

    private static String text(Map<String, Object> body, String field) {
        return body.get(field) instanceof String value ? value : null;
    }

    private static void json(HttpServletResponse response, int status, Map<String, ?> fields) throws IOException {
        response.setStatus(status);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(IdentityClient.json(fields));
    }

    private void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Optional<String> loginUrl;
        try {
            loginUrl = identity.loginUrl(state);
        } catch (IdentityUnavailableException exception) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Sign-in is not available right now");
            return;
        }
        if (loginUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Sign-in is not available yet");
            return;
        }
        String returnTo = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(localPath(request.getParameter(RETURN_PARAMETER)).getBytes(StandardCharsets.UTF_8));
        response.addCookie(cookie(STATE_COOKIE, state + "." + returnTo, STATE_TTL, request));
        response.sendRedirect(loginUrl.get());
    }

    private void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        // The address carries the one-time code; no page reached from here may see it.
        response.setHeader("Referrer-Policy", "no-referrer");
        String[] expected = cookieValue(request, STATE_COOKIE).split("\\.", 2);
        String state = request.getParameter(STATE_PARAMETER);
        response.addCookie(cookie(STATE_COOKIE, "", Duration.ZERO, request));
        if (expected.length != 2 || state == null || !MessageDigest.isEqual(
            expected[0].getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Sign-in could not be completed");
            return;
        }
        Optional<IdentitySession> session;
        try {
            session = identity.exchange(request.getParameter(CODE_PARAMETER));
        } catch (IdentityUnavailableException exception) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Sign-in is not available right now");
            return;
        }
        if (session.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sign-in could not be completed");
            return;
        }
        Duration lifetime = Duration.between(Instant.now(), session.get().expiresAt());
        response.addCookie(cookie(VelodeIdentity.SESSION_COOKIE, session.get().token(), lifetime, request));
        response.sendRedirect(request.getContextPath() + localPath(decoded(expected[1])));
    }

    /**
     * Signing out is a form this application posts. Another site can make a browser follow a link with the session
     * cookie, so a link signs nobody out, and a form must show that this application sent it.
     */
    private void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        if (!"POST".equals(request.getMethod())) {
            response.setHeader("Allow", "POST");
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Sign-out must be a POST");
            return;
        }
        if (!sameOrigin(request, true)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Sign-out must start in this application");
            return;
        }
        // The user is signed out here at once, and at Identity too: the token stops being valid everywhere and
        // the browser passes by Identity, which ends its own sign-in and brings the user back.
        String next = request.getContextPath() + HOME;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (VelodeIdentity.SESSION_COOKIE.equals(cookie.getName())) {
                    next = signedOutAt(cookie.getValue()).orElse(next);
                }
            }
        }
        response.addCookie(cookie(VelodeIdentity.SESSION_COOKIE, "", Duration.ZERO, request));
        response.sendRedirect(next);
    }

    /** A sign-out does not wait for Identity: unreachable, the user is still signed out of this application. */
    private Optional<String> signedOutAt(String token) {
        try {
            return identity.signOut(token);
        } catch (IdentityUnavailableException exception) {
            identity.forget(token);
            return Optional.empty();
        }
    }

    /**
     * Browsers say which site started a request, and a request that names another site is always refused. One that
     * sends neither header is accepted for the JSON steps, whose body another site's form cannot send and which
     * callers other than browsers also use. Signing out has no such body, so there it is refused: current browsers
     * send at least one of the headers with a form this application posts.
     *
     * @param evidenceRequired refuse a request that does not say where it came from
     */
    private boolean sameOrigin(HttpServletRequest request, boolean evidenceRequired) {
        String site = request.getHeader("Sec-Fetch-Site");
        String origin = request.getHeader("Origin");
        if (evidenceRequired && site == null && origin == null) {
            return false;
        }
        return (site == null || "same-origin".equals(site) || "none".equals(site))
            && (origin == null || appOrigin.equals(origin));
    }

    private static String decoded(String value) {
        try {
            return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            return HOME;
        }
    }

    /** Only paths inside this application are followed after sign-in. */
    private static String localPath(String path) {
        return path != null && path.startsWith("/") && !path.startsWith("//") && !path.contains("\\")
            && path.chars().noneMatch(Character::isISOControl) ? path : HOME;
    }

    private static String cookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return "";
    }

    private static Cookie cookie(String name, String value, Duration lifetime, HttpServletRequest request) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
        cookie.setMaxAge((int) Math.max(0, lifetime.toSeconds()));
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }
}
