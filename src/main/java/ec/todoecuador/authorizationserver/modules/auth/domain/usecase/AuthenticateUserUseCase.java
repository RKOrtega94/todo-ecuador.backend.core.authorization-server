package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;

public interface AuthenticateUserUseCase {
    TokenPair execute(String username, String password, DeviceContext device);
}
