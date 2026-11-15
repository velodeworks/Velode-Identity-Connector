package com.velode.identity.connector;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The only settings a connected application provides. None of them is a lasting secret: the invitation only gives
 * the right to ask for a connection, once and within the hour it is valid, and can be removed from the
 * configuration once the application is connected.
 *
 * @param url organization address copied from the Identity panel, such as {@code https://iam.velode.io/o/{organizationId}}
 * @param appUrl public HTTPS origin of this application
 * @param name name suggested to the administrator; defaults to {@code spring.application.name}
 * @param keyRotation how often the connector replaces its own key
 * @param verificationCache how long what Identity said about a session is trusted before Identity is asked
 *     again; zero asks on every call
 * @param verificationCacheSize sessions remembered at once at most; beyond it, the rest are asked about every time
 * @param invitation one-use invitation an administrator created in the Identity panel for this application's
 *     address; only needed to ask for a new connection
 */
@ConfigurationProperties(prefix = "velode.identity")
public record VelodeIdentityProperties(
    String url, String appUrl, String name, Duration keyRotation, Duration verificationCache, Integer verificationCacheSize,
    String invitation
) {

    private static final String ORGANIZATION_SEGMENT = "/o/";
    /** 32 random bytes as Identity writes them, in unpadded base64url. */
    private static final Pattern INVITATION = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Duration DEFAULT_VERIFICATION_CACHE = Duration.ofSeconds(5);
    /** About a hundred bytes each: room for every user at work on one replica of a large application. */
    private static final int DEFAULT_VERIFICATION_CACHE_SIZE = 100_000;
    /** A user who lost access keeps it for this long at most, so it is kept short. */
    private static final Duration LONGEST_VERIFICATION_CACHE = Duration.ofMinutes(1);
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    public VelodeIdentityProperties {
        url = withoutTrailingSlash(url);
        appUrl = withoutTrailingSlash(appUrl);
        keyRotation = keyRotation == null ? Duration.ofDays(30) : keyRotation;
        verificationCache = verificationCache == null ? DEFAULT_VERIFICATION_CACHE : verificationCache;
        if (verificationCache.isNegative() || verificationCache.compareTo(LONGEST_VERIFICATION_CACHE) > 0) {
            throw new IllegalStateException("velode.identity.verification-cache must be between 0 and "
                + LONGEST_VERIFICATION_CACHE.toSeconds() + " seconds");
        }
        verificationCacheSize = verificationCacheSize == null ? DEFAULT_VERIFICATION_CACHE_SIZE : verificationCacheSize;
        if (verificationCacheSize < 1) {
            throw new IllegalStateException("velode.identity.verification-cache-size must be at least 1");
        }
        if (url == null || !url.contains(ORGANIZATION_SEGMENT)) {
            throw new IllegalStateException(
                "velode.identity.url must be the organization address from the Identity panel, ending in /o/{organizationId}");
        }
        secure(url, "velode.identity.url");
        if (appUrl == null || !secure(appUrl, "velode.identity.app-url").getRawPath().isEmpty()) {
            throw new IllegalStateException(
                "velode.identity.app-url must be the public origin of this application, such as https://app.example.com");
        }
        invitation = invitation == null || invitation.isBlank() ? null : invitation.trim();
        if (invitation != null && !INVITATION.matcher(invitation).matches()) {
            throw new IllegalStateException("velode.identity.invitation must be the invitation copied from the Identity"
                + " panel: 43 letters, digits, hyphens or underscores");
        }
    }

    /** The invitation is a secret until it is used or expires, so it stays out of anything that prints the settings. */
    @Override
    public String toString() {
        return "VelodeIdentityProperties[url=" + url + ", appUrl=" + appUrl + "]";
    }

    /** Server-to-server base of the organization. */
    String apiUrl() {
        int segment = url.lastIndexOf(ORGANIZATION_SEGMENT);
        return url.substring(0, segment) + "/api/organizations/" + url.substring(segment + ORGANIZATION_SEGMENT.length());
    }

    /** This application's origin as browsers name it in the {@code Origin} header. */
    String appOrigin() {
        URI uri = URI.create(appUrl);
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        boolean defaultPort = uri.getPort() == -1 || uri.getPort() == ("https".equals(scheme) ? 443 : 80);
        return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + uri.getPort());
    }

    /**
     * Session tokens and connection keys travel to these addresses, so they must be HTTPS. Plain HTTP is accepted
     * only on this machine, for development.
     */
    private static URI secure(String value, String property) {
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException exception) {
            throw new IllegalStateException(property + " is not a valid URL", exception);
        }
        if (uri.getScheme() == null || uri.getHost() == null
            || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalStateException(property + " must be an absolute URL without credentials, query or fragment");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme)
            && !("http".equals(scheme) && LOOPBACK_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT)))) {
            throw new IllegalStateException(property + " must use https; plain http is only accepted for localhost");
        }
        return uri;
    }

    private static String withoutTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
