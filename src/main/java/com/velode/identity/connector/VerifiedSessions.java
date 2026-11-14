package com.velode.identity.connector;

import com.velode.identity.connector.VelodeIdentity.IdentityUser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Remembers for a short time the users Identity confirmed, so that an application which checks its user on every
 * request does not wait for Identity each time. Only confirmed sessions are remembered, each for no longer than
 * the configured time, and never the token itself.
 */
final class VerifiedSessions {

    /** A full memory is emptied rather than left to grow; the sessions in it are simply verified again. */
    private static final int LIMIT = 10_000;

    private final long keptNanos;
    private final LongSupplier nanoTime;
    private final Map<String, Verified> verified = new ConcurrentHashMap<>();

    /**
     * @param kept how long a confirmation is trusted; zero remembers nothing
     * @param nanoTime a clock that only moves forward
     */
    VerifiedSessions(Duration kept, LongSupplier nanoTime) {
        this.keptNanos = kept.toNanos();
        this.nanoTime = nanoTime;
    }

    /** The user Identity confirmed for this token a moment ago, if it did. */
    Optional<IdentityUser> find(String token) {
        if (keptNanos == 0) {
            return Optional.empty();
        }
        String key = key(token);
        Verified found = verified.get(key);
        if (found == null) {
            return Optional.empty();
        }
        if (nanoTime.getAsLong() - found.at() >= keptNanos) {
            verified.remove(key, found);
            return Optional.empty();
        }
        return Optional.of(found.user());
    }

    void remember(String token, IdentityUser user) {
        if (keptNanos == 0) {
            return;
        }
        long now = nanoTime.getAsLong();
        if (verified.size() >= LIMIT) {
            verified.values().removeIf(old -> now - old.at() >= keptNanos);
            if (verified.size() >= LIMIT) {
                verified.clear();
            }
        }
        verified.put(key(token), new Verified(user, now));
    }

    void forget(String token) {
        if (token != null && !verified.isEmpty()) {
            verified.remove(key(token));
        }
    }

    /** Tokens are bearer secrets, so the memory is indexed by their digest. */
    private static String key(String token) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    private record Verified(IdentityUser user, long at) {
    }
}
