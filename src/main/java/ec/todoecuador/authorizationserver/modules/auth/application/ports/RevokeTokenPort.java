package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.domain.exception.SessionOwnershipException;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.AuthSession;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RevokeTokenUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevokeTokenPort implements RevokeTokenUseCase {

    private final AuthSessionRepository authSessionRepository;

    @Override
    @Transactional
    public void revokeCurrentSession(String accessTokenJti, String principalName) {
        authSessionRepository.findByAccessTokenJti(accessTokenJti).ifPresent(session -> {
            verifyOwnership(session, principalName);
            authSessionRepository.revokeById(session.id());
            log.info("Session [{}] revoked on logout for user '{}'.", session.id(), principalName);
        });
    }

    @Override
    @Transactional
    public void revokeSessionById(UUID sessionId, String principalName) {
        AuthSession session = authSessionRepository.findActiveSessionsByUsername(principalName).stream().filter(s -> s.id().equals(sessionId)).findFirst().orElseThrow(SessionOwnershipException::new);

        verifyOwnership(session, principalName);
        authSessionRepository.revokeById(session.id());
        log.info("Session [{}] revoked by user '{}'.", sessionId, principalName);
    }

    @Override
    @Transactional
    public void revokeAllOtherSessions(UUID currentSessionId, String principalName) {
        authSessionRepository.revokeAllByUsernameExcept(principalName, currentSessionId);
        log.info("All other sessions revoked for user '{}'.", principalName);
    }

    private void verifyOwnership(AuthSession session, String principalName) {
        if (!session.username().equals(principalName)) {
            throw new SessionOwnershipException();
        }
    }
}
