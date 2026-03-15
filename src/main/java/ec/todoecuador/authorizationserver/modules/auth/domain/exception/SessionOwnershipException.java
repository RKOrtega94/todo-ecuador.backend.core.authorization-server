package ec.todoecuador.authorizationserver.modules.auth.domain.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class SessionOwnershipException extends RuntimeException {
    public SessionOwnershipException() {
        super("Session does not belong to the authenticated user");
    }
}
