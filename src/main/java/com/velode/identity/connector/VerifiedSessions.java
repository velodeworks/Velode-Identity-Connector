package com.velode.identity.connector;

import com.velode.identity.connector.VelodeIdentity.IdentityUser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Remembers for a short time what Identity said about a session, so that an application which checks its user on
 * every request does not wait for Identity each time. A confirmed session and a refused one are each remembered
 * for no longer than the configured time, and never the token itself.
 */
final class VerifiedSessions {

    /** Refused tokens are whatever a browser sends, so they get a small part of the memory of their own. */
    private static final int REFUSED_SHARE = 10;
    private static final long SWEEP_EVERY_NANOS = Duration.ofSeconds(1).toNanos();

    private final long keptNanos;
    private final long renewAfterNanos;
    private final int limit;
    private final LongSupplier nanoTime;
    private final Map<String, Confirmed> confirmed = new ConcurrentHashMap<>();
    private final Map<String, Long> refused = new ConcurrentHashMap<>();
    private final AtomicLong sweptAt;

    /**
     * @param kept how long what Identity said is trusted; zero remembers nothing
     * @param limit sessions remembered at most; beyond it, new ones are simply asked about every time
     * @param nanoTime a clock that only moves forward
     */
    VerifiedSessions(Duration kept, int limit, LongSupplier nanoTime) {
        this.keptNanos = kept.toNanos();
        // Renewed during the last fifth of its time, a session in use is confirmed again before anyone waits.
        this.renewAfterNanos = keptNanos - keptNanos / 5;
        this.limit = limit;
        this.nanoTime = nanoTime;
        this.sweptAt = new AtomicLong(nanoTime.getAsLong());
    }

    boolean remembers() {
        return keptNanos > 0;
    }

    /** What is remembered about the session under this key, or null. */
    Remembered find(String key) {
        long now = nanoTime.getAsLong();
        Confirmed user = confirmed.get(key);
        if (user != null) {
            long age = now - user.at();
            if (age < keptNanos) {
                return new Remembered(user.user(), age >= renewAfterNanos);
            }
            confirmed.remove(key, user);
        }
        Long refusedAt = refused.get(key);
        if (refusedAt != null) {
            if (now - refusedAt < keptNanos) {
                return Remembered.REFUSED;
            }
            refused.remove(key, refusedAt);
        }
        return null;
    }

    void confirm(String key, IdentityUser user) {
        if (!remembers()) {
            return;
        }
        long now = nanoTime.getAsLong();
        refused.remove(key);
        if (confirmed.containsKey(key) || roomIn(confirmed, limit, now)) {
            confirmed.put(key, new Confirmed(user, now));
        }
    }

    void refuse(String key) {
        confirmed.remove(key);
        if (!remembers()) {
            return;
        }
        long now = nanoTime.getAsLong();
        if (refused.containsKey(key) || roomIn(refused, Math.max(1, limit / REFUSED_SHARE), now)) {
            refused.put(key, now);
        }
    }

    void forget(String key) {
        confirmed.remove(key);
        refused.remove(key);
    }

    /**
     * Whether another session fits. A full memory drops what has expired, at most once a second, and is never
     * emptied: the sessions already remembered keep being answered without Identity.
     */
    private boolean roomIn(Map<String, ?> memory, int most, long now) {
        if (memory.size() < most) {
            return true;
        }
        long last = sweptAt.get();
        if (now - last >= SWEEP_EVERY_NANOS && sweptAt.compareAndSet(last, now)) {
            confirmed.values().removeIf(old -> now - old.at() >= keptNanos);
            refused.values().removeIf(at -> now - at >= keptNanos);
        }
        return memory.size() < most;
    }

    /** Tokens are bearer secrets, so the memory is indexed by their digest. */
    static String key(String token) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    /**
     * What Identity said about a session a moment ago.
     *
     * @param user the user it confirmed, or null when it refused the session
     * @param dueForRenewal whether Identity should be asked again soon, while this answer still stands
     */
    record Remembered(IdentityUser user, boolean dueForRenewal) {

        static final Remembered REFUSED = new Remembered(null, false);
    }

    private record Confirmed(IdentityUser user, long at) {
    }
}
