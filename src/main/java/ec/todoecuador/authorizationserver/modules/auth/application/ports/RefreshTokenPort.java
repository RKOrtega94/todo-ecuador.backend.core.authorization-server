package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.application.service.TokenIssuanceService;
import ec.todoecuador.authorizationserver.modules.auth.domain.exception.InvalidRefreshTokenException;
import ec.todoecuador.authorizationserver.modules.auth.domain.exception.RefreshTokenReplayException;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.AuthSession;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.UserRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RefreshTokenUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenPort implements RefreshTokenUseCase {

    private final AuthSessionRepository authSessionRepository;
    private final TokenIssuanceService tokenIssuanceService;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public TokenPair execute(String refreshToken, DeviceContext device) {
        String hash = tokenIssuanceService.hashToken(refreshToken);

        AuthSession session = authSessionRepository.findByRefreshTokenHash(hash)
                .orElseThrow(InvalidRefreshTokenException::new);

        // Token replay: already revoked refresh token was reused — potential theft
        if (session.isRevoked()) {
            log.warn("Refresh token replay detected for user '{}'. Revoking all sessions.", session.getUsername());
            authSessionRepository.revokeAllByUsername(session.getUsername());
            throw new RefreshTokenReplayException(session.getUsername());
        }

        if (session.isExpired(Instant.now())) {
            authSessionRepository.revokeById(session.getId());
            throw new InvalidRefreshTokenException();
        }

        // Invalidate consumed refresh token (rotation: one-time use)
        authSessionRepository.revokeById(session.getId());

        // Issue new token pair with user's actual roles
        var authorities = userRepository.findByUsername(session.getUsername())
            .map(user -> user.getRoles().isEmpty()
                ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
                : user.getRoles().stream()
                    .map(role -> role.getName())
                    .map(roleName -> roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName)
                    .map(SimpleGrantedAuthority::new)
                    .toList())
            .orElse(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

        var authentication = UsernamePasswordAuthenticationToken.authenticated(
            session.getUsername(), null, authorities);

        log.debug("Refresh token rotated for user '{}', device '{}'.", session.getUsername(), session.getDeviceId());
        return tokenIssuanceService.issue(authentication, device);
    }
}
