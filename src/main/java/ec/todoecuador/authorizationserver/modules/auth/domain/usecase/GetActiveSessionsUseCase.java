package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.ActiveSession;

import java.util.List;

public interface GetActiveSessionsUseCase {
    /**
     * Returns all active (non-revoked, non-expired) sessions for the given user.
     *
     * @param principalName  authenticated username
     * @param currentJti     JTI of the currently used access token — used to mark the current session
     */
    List<ActiveSession> execute(String principalName, String currentJti);
}
