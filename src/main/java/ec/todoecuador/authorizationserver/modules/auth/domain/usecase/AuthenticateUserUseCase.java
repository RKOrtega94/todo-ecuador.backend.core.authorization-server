package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import org.springframework.security.core.Authentication;

public interface AuthenticateUserUseCase {
    Authentication execute(String username, String password);
}
