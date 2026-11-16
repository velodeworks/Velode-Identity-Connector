package com.velode.identity.connector;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.boot.json.JsonParseException;

/**
 * Sends the connector's JSON calls to one organization of Identity.
 */
class IdentityClient {

    private static final String KEY_HEADER = "X-Server-Connection-Key";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    /**
     * Identity's answers stay under 2 KB. Something broken or hostile in front of it could send far more, and every
     * application would hold it in memory, so the rest of a longer answer is not read.
     */
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private static final String DISCOVERY_PATH = "/.well-known/velode-identity";
    private static final String ORGANIZATION_SEGMENT = "/o/";

    private final String organizationUrl;
    /** Read from Identity once and kept: a process that must read it again is restarted. */
    private volatile Addresses addresses;
    // A redirect could carry the connection key to another host, so Identity's answer is taken as it is.
    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(TIMEOUT)
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    /** @param organizationUrl the organization address from the Identity panel, the only one this application is given */
    IdentityClient(String organizationUrl) {
        this.organizationUrl = organizationUrl;
    }

    /** Identity's sign-in page for the organization, to which a browser is sent. */
    String loginUrl() {
        return addresses().loginUrl();
    }

    /** Returns the HTTP status with the {@code data} object of a success or the fields of an error. */
    Response post(String path, String key, Map<String, String> body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(addresses().apiUrl() + path))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json(body)));
        if (key != null) {
            request.header(KEY_HEADER, key);
        }
        return send(request.build());
    }

    /**
     * Where Identity says the organization is reached. Identity tells; the connector deduces nothing from the
     * address it was given. Both addresses must be on the host of that address, since session tokens and the
     * connection key travel to them.
     */
    private Addresses addresses() {
        Addresses known = addresses;
        if (known != null) {
            return known;
        }
        Response response = send(HttpRequest.newBuilder(URI.create(organizationUrl + DISCOVERY_PATH))
            .timeout(TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build());
        String loginUrl = response.text("loginUrl");
        String apiUrl = response.text("apiUrl");
        String organizationId = organizationUrl.substring(
            organizationUrl.lastIndexOf(ORGANIZATION_SEGMENT) + ORGANIZATION_SEGMENT.length());
        if (response.status() != 200 || !organizationId.equalsIgnoreCase(response.text("organizationId"))
            || !onOrganizationHost(loginUrl) || !onOrganizationHost(apiUrl)) {
            throw new IdentityUnavailableException("Velode Identity did not say where the organization at "
                + organizationUrl + " is reached; check velode.identity.url and that Identity is up to date", null);
        }
        known = new Addresses(loginUrl, apiUrl);
        addresses = known;
        return known;
    }

    private boolean onOrganizationHost(String candidate) {
        return onIdentityHost(candidate) && URI.create(candidate).getRawQuery() == null;
    }

    /** Whether an address Identity names for the browser is on the host this application was given. */
    boolean onIdentityHost(String candidate) {
        if (candidate == null) {
            return false;
        }
        try {
            URI given = URI.create(organizationUrl);
            URI told = URI.create(candidate);
            return told.getRawUserInfo() == null && told.getRawFragment() == null
                && given.getScheme().equalsIgnoreCase(told.getScheme())
                && given.getHost().equalsIgnoreCase(told.getHost())
                && given.getPort() == told.getPort();
        } catch (IllegalArgumentException | NullPointerException exception) {
            return false;
        }
    }

    private Response send(HttpRequest request) {
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream answer = response.body()) {
                byte[] bytes = answer.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES) {
                    throw new IdentityUnavailableException(
                        "Velode Identity answered with more than " + MAX_RESPONSE_BYTES + " bytes", null);
                }
                return new Response(response.statusCode(),
                    data(response.statusCode(), new String(bytes, StandardCharsets.UTF_8)));
            }
        } catch (IOException exception) {
            throw new IdentityUnavailableException("Velode Identity could not be reached", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IdentityUnavailableException("Interrupted while calling Velode Identity", exception);
        }
    }

    private static Map<String, Object> data(int status, String text) {
        if (text.isBlank()) {
            return Map.of();
        }
        Map<String, Object> body;
        try {
            body = new BasicJsonParser().parseMap(text);
        } catch (JsonParseException exception) {
            // A proxy in front of Identity answered; only the status is meaningful.
            return Map.of();
        }
        return (status == 200 ? body.get("data") : body) instanceof Map<?, ?> data
            ? data.entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .collect(Collectors.toMap(entry -> String.valueOf(entry.getKey()), Map.Entry::getValue))
            : Map.of();
    }

    /** A flat object: booleans as they are and every other value as escaped text, which is all the connector writes. */
    static String json(Map<String, ?> body) {
        return body.entrySet().stream()
            .map(entry -> '"' + entry.getKey() + "\":" + (entry.getValue() instanceof Boolean flag
                ? flag.toString() : '"' + escape(String.valueOf(entry.getValue())) + '"'))
            .collect(Collectors.joining(",", "{", "}"));
    }

    private static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (char character : value.toCharArray()) {
            if (character == '"' || character == '\\') {
                escaped.append('\\').append(character);
            } else if (character < 0x20) {
                escaped.append(String.format("\\u%04x", (int) character));
            } else {
                escaped.append(character);
            }
        }
        return escaped.toString();
    }

    private record Addresses(String loginUrl, String apiUrl) {
    }

    record Response(int status, Map<String, Object> data) {

        /** Identity refused the connection key itself, not the user token or code sent with it. */
        boolean keyRefused() {
            return status == 401 && "INVALID_CONNECTION_KEY".equals(text("error"));
        }

        /** Identity has not seen the key and was not sent an invitation it accepts for this application. */
        boolean invitationRequired() {
            return status == 403 && "CONNECTION_INVITATION_REQUIRED".equals(text("error"));
        }

        String text(String field) {
            Object value = data.get(field);
            return value == null ? null : value.toString();
        }
    }
}
