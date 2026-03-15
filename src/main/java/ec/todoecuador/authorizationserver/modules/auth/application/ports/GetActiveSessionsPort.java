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
        return authSessionRepository.findActiveSessionsByUsername(principalName)
                .stream()
                .map(s -> new ActiveSession(
                        s.getId(),
                        s.getDeviceId(),
                        s.getDeviceName(),
                        s.getUserAgent(),
                        s.getIpAddress(),
                        s.getCreatedAt(),
                        s.getLastSeenAt(),
                        s.getAccessTokenJti().equals(currentJti)))
                .toList();
    }
}
