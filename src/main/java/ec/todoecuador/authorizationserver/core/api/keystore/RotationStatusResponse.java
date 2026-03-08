package ec.todoecuador.authorizationserver.core.api.keystore;

import java.time.Instant;

public record RotationStatusResponse(
        boolean success,
        Instant expiresAt,
        String message,
        Instant rotatedAt
) {
}
