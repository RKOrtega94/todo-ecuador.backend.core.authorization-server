package ec.todoecuador.authorizationserver.modules.auth.domain.repository;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.AuthSession;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {
    void save(AuthSession session);

    Optional<AuthSession> findByAccessTokenJti(String jti);

    Optional<AuthSession> findByRefreshTokenHash(String refreshTokenHash);

    /**
     * Returns non-revoked, non-expired sessions for the user ordered by createdAt ascending.
     */
    List<AuthSession> findActiveSessionsByUsername(String username);

    long countActiveSessionsByUsername(String username);

    /**
     * Finds the oldest active session for eviction when the session limit is reached.
     */
    Optional<AuthSession> findOldestActiveSessionByUsername(String username);

    void revokeById(UUID id);

    void revokeAllByUsernameExcept(String username, UUID exceptSessionId);

    void revokeAllByUsername(String username);

    void deleteOldestSessionByUsername(String username);
}
