package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import java.util.UUID;

public interface RevokeTokenUseCase {
    /** Revokes the session associated with the given access-token JTI (logout). */
    void revokeCurrentSession(String accessTokenJti, String principalName);

    /** Revokes a specific session by its ID, ensuring it belongs to principalName. */
    void revokeSessionById(UUID sessionId, String principalName);

    /** Revokes all sessions for principalName except the current one. */
    void revokeAllOtherSessions(UUID currentSessionId, String principalName);
}
