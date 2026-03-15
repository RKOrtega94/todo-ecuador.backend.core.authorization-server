package ec.todoecuador.authorizationserver.modules.auth.domain.model;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Value object returned after successful authentication or token refresh.
 * Contains both the short-lived access token and the rotating refresh token.
 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        UUID sessionId,
        List<String> roles) {

    public TokenPair {
        if (tokenType == null || tokenType.isBlank()) tokenType = "Bearer";
        if (roles == null) roles = Collections.emptyList();
    }
}
