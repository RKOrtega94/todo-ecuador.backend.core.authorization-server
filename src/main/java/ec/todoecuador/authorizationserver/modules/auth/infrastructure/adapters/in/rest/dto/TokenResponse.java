package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

/**
 * REST response returned after a successful login or token refresh.
 */
@Data
@Builder
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;
    private UUID sessionId;

    public static TokenResponse from(TokenPair pair) {
        return TokenResponse.builder() //
                .accessToken(pair.accessToken()) //
                .refreshToken(pair.refreshToken()) //
                .tokenType(pair.tokenType()) //
                .expiresIn(pair.expiresIn()) //
                .sessionId(pair.sessionId()) //
                .build();
    }
}
