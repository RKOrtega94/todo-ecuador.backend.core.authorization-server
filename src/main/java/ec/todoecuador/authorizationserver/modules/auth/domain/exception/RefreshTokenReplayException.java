package ec.todoecuador.authorizationserver.modules.auth.domain.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when a refresh token that was already rotated is used again.
 * This is a strong indicator of token theft; all sessions for the user are revoked.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class RefreshTokenReplayException extends RuntimeException {
    private final String username;

    public RefreshTokenReplayException(String username) {
        super("Potential token theft detected for user '" + username + "'. All sessions revoked.");
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
