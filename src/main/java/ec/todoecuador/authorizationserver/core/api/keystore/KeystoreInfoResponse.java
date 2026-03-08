package ec.todoecuador.authorizationserver.core.api.keystore;

import java.time.Instant;

public record KeystoreInfoResponse(
        String alias,
        String path,
        Instant expiresAt,
        long daysUntilExpiry,
        boolean backupAvailable
) {
}
