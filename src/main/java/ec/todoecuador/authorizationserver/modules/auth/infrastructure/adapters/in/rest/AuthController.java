package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.AuthenticateUserUseCase;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.GetActiveSessionsUseCase;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RefreshTokenUseCase;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RevokeTokenUseCase;
import ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto.LoginRequest;
import ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto.RefreshTokenRequest;
import ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto.SessionResponse;
import ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto.TokenResponse;
import ec.todoecuador.common.http.CustomApiResponse;
import ec.todoecuador.common.http.CustomSuccessResponse;
import ec.todoecuador.common.i18n.I18nKeys;
import ec.todoecuador.common.i18n.MessageResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

import static ec.todoecuador.authorizationserver.modules.auth.application.utils.RequestUtils.extractDeviceContext;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String HEADER_X_DEVICE_ID = "X-Device-Id";
    private static final String HEADER_X_DEVICE_NAME = "X-Device-Name";

    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final RevokeTokenUseCase revokeTokenUseCase;
    private final GetActiveSessionsUseCase getActiveSessionsUseCase;

    private final MessageResolver messageResolver;

    /**
     * Authenticates the user with username and password and returns a token pair.
     * The response includes an access token (JWT), a one-time refresh token (opaque),
     * and the session ID for the device.
     *
     * <p>On reaching the maximum concurrent sessions, the oldest session is automatically evicted.
     *
     * <p>Rate limiting: {@code auth.server.rate-limit.login-max-requests} per window per IP.
     */
    @PostMapping("/login")
    public ResponseEntity<CustomApiResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {

        DeviceContext device = extractDeviceContext(request);
        TokenPair tokens = authenticateUserUseCase.execute(loginRequest.getUsername(), loginRequest.getPassword(), device);
        return ResponseEntity.ok(CustomSuccessResponse.ok(messageResolver.get(I18nKeys.LOGIN_SUCCESSFULLY), TokenResponse.from(tokens)));
    }

    /**
     * Issues a new token pair using a valid refresh token (rotation).
     * The supplied refresh token is immediately invalidated — using the same token twice
     * is treated as evidence of token theft and triggers revocation of ALL sessions.
     *
     * <p>Rate limiting: {@code auth.server.rate-limit.refresh-max-requests} per window per IP.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest refreshRequest, HttpServletRequest request) {

        DeviceContext device = extractDeviceContext(request);
        TokenPair tokens = refreshTokenUseCase.execute(refreshRequest.getRefreshToken(), device);

        return ResponseEntity.ok(TokenResponse.from(tokens));
    }

    /**
     * Logs out the currently authenticated user by revoking the active session
     * (access + refresh tokens are immediately invalidated server-side).
     * Requires a valid Bearer token in the Authorization header.
     */
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {
        revokeTokenUseCase.revokeCurrentSession(jwt.getId(), jwt.getSubject());
        return ResponseEntity.noContent().build();
    }

    /**
     * Returns the list of active sessions for the authenticated user.
     * The current session is flagged with {@code current: true}.
     */
    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<SessionResponse>> getSessions(@AuthenticationPrincipal Jwt jwt) {
        String principalName = jwt.getSubject();
        String currentJti = jwt.getId();

        List<SessionResponse> sessions = getActiveSessionsUseCase.execute(principalName, currentJti).stream().map(SessionResponse::from).toList();

        return ResponseEntity.ok(sessions);
    }

    /**
     * Revokes a specific session by its ID.
     * Only the authenticated user can revoke their own sessions.
     */
    @DeleteMapping("/sessions/{sessionId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> revokeSession(@PathVariable UUID sessionId, @AuthenticationPrincipal Jwt jwt) {

        revokeTokenUseCase.revokeSessionById(sessionId, jwt.getSubject());
        return ResponseEntity.noContent().build();
    }

    /**
     * Revokes all sessions for the authenticated user except the current one.
     * Useful for "logout all other devices".
     */
    @DeleteMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> revokeOtherSessions(@AuthenticationPrincipal Jwt jwt) {
        String sessionIdClaim = jwt.getClaimAsString("session_id");
        UUID currentSessionId = UUID.fromString(sessionIdClaim);

        revokeTokenUseCase.revokeAllOtherSessions(currentSessionId, jwt.getSubject());
        return ResponseEntity.noContent().build();
    }
}

