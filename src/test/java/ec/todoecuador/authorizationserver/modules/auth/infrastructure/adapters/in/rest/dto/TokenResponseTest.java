package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenResponseTest {

    @Test
    void fromCopiesFieldsFromTokenPair() {
        UUID sessionId = UUID.randomUUID();
        List<String> roles = List.of("SYSTEM_ADMIN", "FACTOR_PASSWORD");

        TokenPair pair = new TokenPair("access", "refresh", "Bearer", 900L, sessionId, roles);

        TokenResponse response = TokenResponse.from(pair);

        assertEquals("access", response.getAccessToken());
        assertEquals("refresh", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(900L, response.getExpiresIn());
        assertEquals(sessionId, response.getSessionId());
    }
}
