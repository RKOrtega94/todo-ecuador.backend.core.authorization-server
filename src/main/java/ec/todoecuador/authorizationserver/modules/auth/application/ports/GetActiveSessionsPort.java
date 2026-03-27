package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.ActiveSession;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.GetActiveSessionsUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class GetActiveSessionsPort implements GetActiveSessionsUseCase {

    private final AuthSessionRepository authSessionRepository;

    @Override
    public List<ActiveSession> execute(String principalName, String currentJti) {
        return authSessionRepository.findActiveSessionsByUsername(principalName).stream().map(s -> new ActiveSession(s.id(), s.deviceId(), s.deviceName(), s.userAgent(), s.ipAddress(), s.createdAt(), s.lastSeenAt(), s.accessTokenJti().equals(currentJti))).toList();
    }
}
