package ec.todoecuador.authorizationserver.modules.auth.domain.model;

import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain entity representing an active authentication session.
 * Tracks per-device token lifecycle: issuance, rotation, revocation and expiry.
 * <p>
 * Immutable record — use {@link #withLastSeenAt} and {@link #withRevokedAt}
 * to produce updated copies instead of mutating state.
 */
@Builder
public record AuthSession(UUID id, String username, String deviceId, String deviceName, String userAgent,
                          String ipAddress, String accessTokenJti, String refreshTokenHash, Instant createdAt,
                          Instant lastSeenAt, Instant expiresAt, Instant revokedAt) {

    // --- Domain behaviour ---

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }

    // --- Wither methods for mutable lifecycle fields ---

    public AuthSession withLastSeenAt(Instant lastSeenAt) {
        return new AuthSession(id, username, deviceId, deviceName, userAgent, ipAddress, accessTokenJti, refreshTokenHash, createdAt, lastSeenAt, expiresAt, revokedAt);
    }

    public AuthSession withRevokedAt(Instant revokedAt) {
        return new AuthSession(id, username, deviceId, deviceName, userAgent, ipAddress, accessTokenJti, refreshTokenHash, createdAt, lastSeenAt, expiresAt, revokedAt);
    }
}