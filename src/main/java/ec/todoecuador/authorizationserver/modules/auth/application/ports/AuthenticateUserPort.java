package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.application.service.TokenIssuanceService;
import ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities.UserForeignEntity;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.UserRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.AuthenticateUserUseCase;
import ec.todoecuador.common.i18n.I18nKeys;
import ec.todoecuador.common.i18n.MessageResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthenticateUserPort implements AuthenticateUserUseCase {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final TokenIssuanceService tokenIssuanceService;
    private final Clock clock;
    private final MessageResolver messageResolver;

    @Override
    public TokenPair execute(String username, String password, DeviceContext device) {
        UserForeignEntity user = userRepository.findByUsername(username).orElseThrow(this::invalidCredentials);

        if (isInvalidUserState(user)) throw invalidCredentials();

        Authentication authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authRequest);
        } catch (AuthenticationException _) {
            throw invalidCredentials();
        }

        return tokenIssuanceService.issue(authentication, device);
    }

    private boolean isInvalidUserState(UserForeignEntity user) {
        return Boolean.FALSE.equals(user.getEnabled()) || Boolean.TRUE.equals(user.getLocked()) || isPasswordExpired(user.getPasswordExpiration());
    }

    private boolean isPasswordExpired(Instant passwordExpiration) {
        return passwordExpiration != null && !passwordExpiration.isAfter(Instant.now(clock));
    }

    private BadCredentialsException invalidCredentials() {
        return new BadCredentialsException(messageResolver.get(I18nKeys.AUTH_INVALID_CREDENTIALS));
    }
}

