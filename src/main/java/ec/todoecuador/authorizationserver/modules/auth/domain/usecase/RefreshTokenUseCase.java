package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;

public interface RefreshTokenUseCase {
    /**
     * Validates the given refresh token, revokes it (rotation), and issues a new token pair.
     * If the refresh token has already been used (replay), all sessions for the user are revoked
     * to mitigate token theft.
     */
    TokenPair execute(String refreshToken, DeviceContext device);
}
