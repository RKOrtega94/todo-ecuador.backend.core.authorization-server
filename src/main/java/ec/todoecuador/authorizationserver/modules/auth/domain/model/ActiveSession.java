package ec.todoecuador.authorizationserver.modules.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Read model returned to the client when listing active sessions.
 * Does not expose sensitive token data.
 */
public record ActiveSession(
        UUID id,
        String deviceId,
        String deviceName,
        String userAgent,
        String ipAddress,
        Instant createdAt,
        Instant lastSeenAt,
        boolean current) {}
