package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities.UserForeignEntity;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.UserRepository;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.AuthenticateUserUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthenticateUserPort implements AuthenticateUserUseCase {
    private static final String INVALID_CREDENTIALS_MESSAGE = "Invalid username or password";

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final Clock clock;

    @Override
    public Authentication execute(String username, String password) {
        UserForeignEntity user = userRepository.findByUsername(username)
                .orElseThrow(AuthenticateUserPort::invalidCredentials);

        if (isInvalidUserState(user)) {
            throw invalidCredentials();
        }

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(username, password);

        try {
            return authenticationManager.authenticate(authenticationRequest);
        } catch (BadCredentialsException ex) {
            throw invalidCredentials();
        }
    }

    private boolean isInvalidUserState(UserForeignEntity user) {
        return Boolean.FALSE.equals(user.getEnabled())
                || Boolean.TRUE.equals(user.getLocked())
                || isPasswordExpired(user.getPasswordExpiration());
    }

    private boolean isPasswordExpired(Instant passwordExpiration) {
        return passwordExpiration != null && !passwordExpiration.isAfter(Instant.now(clock));
    }

    private static BadCredentialsException invalidCredentials() {
        return new BadCredentialsException(INVALID_CREDENTIALS_MESSAGE);
    }
}

