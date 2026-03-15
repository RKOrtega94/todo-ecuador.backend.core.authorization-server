package ec.todoecuador.authorizationserver.core.security;

import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Custom {@link OAuth2TokenValidator} that checks whether a JWT's JTI has been revoked
 * by inspecting the {@code auth_sessions} table.
 *
 * <p>Tokens issued through the standard OAuth2 Authorization Server flow (no JTI in auth_sessions)
 * are allowed through without errors — this validator only rejects tokens whose JTI is explicitly
 * flagged as revoked.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenRevocationValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error REVOKED_ERROR = new OAuth2Error(
            "invalid_token", "Token has been revoked", null);

    private final AuthSessionRepository authSessionRepository;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String jti = token.getId();
        if (jti == null || jti.isBlank()) {
            return OAuth2TokenValidatorResult.success();
        }

        try {
            return authSessionRepository
                    .findByAccessTokenJti(jti)
                    .map(session -> {
                        if (session.isRevoked()) {
                            log.debug("Rejected revoked token JTI='{}'.", jti);
                            return OAuth2TokenValidatorResult.failure(REVOKED_ERROR);
                        }
                        return OAuth2TokenValidatorResult.success();
                    })
                    .orElse(OAuth2TokenValidatorResult.success());
        } catch (Exception e) {
            // Fail-open on DB error to avoid blocking all traffic when the DB is temporarily unavailable
            log.warn("Token revocation check failed (fail-open): {}", e.getMessage());
            return OAuth2TokenValidatorResult.success();
        }
    }
}
