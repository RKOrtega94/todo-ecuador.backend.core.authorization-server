package ec.todoecuador.authorizationserver.core.security;

import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RevokeTokenUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * Logout handler that revokes the current session's tokens when the user logs out.
 * Works alongside Spring Security's standard session-invalidation logout handler.
 */
@Slf4j
@RequiredArgsConstructor
public class TokenRevocationLogoutHandler implements LogoutHandler {

    private final RevokeTokenUseCase revokeTokenUseCase;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String jti       = jwt.getId();
            String principal = jwtAuth.getName();

            if (jti != null && !jti.isBlank()) {
                try {
                    revokeTokenUseCase.revokeCurrentSession(jti, principal);
                    log.info("Token revoked on logout for user '{}'.", principal);
                } catch (Exception e) {
                    log.warn("Failed to revoke token on logout for '{}': {}", principal, e.getMessage());
                }
            }
        }
    }
}
