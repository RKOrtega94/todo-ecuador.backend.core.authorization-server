package ec.todoecuador.authorizationserver.modules.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain entity representing an active authentication session.
 * Tracks per-device token lifecycle: issuance, rotation, revocation and expiry.
 */
public class AuthSession {

    private final UUID id;
    private final String username;
    private final String deviceId;
    private final String deviceName;
    private final String userAgent;
    private final String ipAddress;
    private final String accessTokenJti;
    private final String refreshTokenHash;
    private final Instant createdAt;
    private Instant lastSeenAt;
    private final Instant expiresAt;
    private Instant revokedAt;

    public AuthSession(
            UUID id,
            String username,
            String deviceId,
            String deviceName,
            String userAgent,
            String ipAddress,
            String accessTokenJti,
            String refreshTokenHash,
            Instant createdAt,
            Instant lastSeenAt,
            Instant expiresAt,
            Instant revokedAt) {
        this.id = id;
        this.username = username;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
        this.accessTokenJti = accessTokenJti;
        this.refreshTokenHash = refreshTokenHash;
        this.createdAt = createdAt;
        this.lastSeenAt = lastSeenAt;
        this.expiresAt = expiresAt;
        this.revokedAt = revokedAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }

    // --- Getters ---

    public UUID getId()                { return id; }
    public String getUsername()        { return username; }
    public String getDeviceId()        { return deviceId; }
    public String getDeviceName()      { return deviceName; }
    public String getUserAgent()       { return userAgent; }
    public String getIpAddress()       { return ipAddress; }
    public String getAccessTokenJti()  { return accessTokenJti; }
    public String getRefreshTokenHash(){ return refreshTokenHash; }
    public Instant getCreatedAt()      { return createdAt; }
    public Instant getLastSeenAt()     { return lastSeenAt; }
    public Instant getExpiresAt()      { return expiresAt; }
    public Instant getRevokedAt()      { return revokedAt; }
}
