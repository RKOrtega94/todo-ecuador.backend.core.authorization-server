package ec.todoecuador.authorizationserver.modules.auth.application.service;

import ec.todoecuador.authorizationserver.core.properties.SecurityProperties;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.AuthSession;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Core service responsible for issuing JWT access tokens and opaque refresh tokens,
 * persisting sessions with device metadata, and enforcing the maximum-sessions-per-user policy
 * by evicting the oldest active session when the limit is reached.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenIssuanceService {

    private final JwtEncoder jwtEncoder;
    private final AuthSessionRepository authSessionRepository;
    private final SecurityProperties securityProperties;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Issues a new token pair for the authenticated user.
     * Evicts the oldest active session if the per-user session limit is reached.
     */
    @Transactional
    public TokenPair issue(Authentication authentication, DeviceContext device) {
        String username = authentication.getName();
        String jti = UUID.randomUUID().toString();
        UUID sessionId = UUID.randomUUID();
        Instant now = Instant.now();

        List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).map(authority -> authority.toUpperCase().startsWith("ROLE_") ? authority.substring(5).toUpperCase() : authority.toUpperCase()).toList();

        Duration accessTtl = Duration.ofMinutes(securityProperties.getAccessTokenTtlMinutes());
        Duration refreshTtl = Duration.ofHours(securityProperties.getRefreshTokenTtlHours());

        // Issue JWT access token
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(securityProperties.getIssuer()).issuedAt(now).expiresAt(now.plus(accessTtl)).subject(username).id(jti).claim("session_id", sessionId.toString()).claim("device_id", device.deviceId()).claim("authorities", roles).build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(header, claims));

        // Issue opaque refresh token (raw value is returned to the client, only the hash is stored)
        String rawRefreshToken = generateOpaqueToken();
        String refreshTokenHash = hashToken(rawRefreshToken);

        // Enforce max-sessions policy: evict oldest active session if needed
        long activeSessions = authSessionRepository.countActiveSessionsByUsername(username);
        if (activeSessions >= securityProperties.getMaxSessionsPerUser()) {
            authSessionRepository.findOldestActiveSessionByUsername(username).ifPresent(oldest -> {
                log.info("Max sessions reached for '{}'. Evicting oldest session [{}].", username, oldest.getId());
                authSessionRepository.revokeById(oldest.getId());
            });
        }

        // Persist the new session
        AuthSession session = new AuthSession(sessionId, username, device.deviceId(), device.deviceName(), device.userAgent(), device.ipAddress(), jti, refreshTokenHash, now, now, now.plus(refreshTtl), null);

        authSessionRepository.save(session);
        log.debug("New auth session [{}] created for user '{}' from device '{}'.", sessionId, username, device.deviceId());

        return new TokenPair(jwt.getTokenValue(), rawRefreshToken, "Bearer", accessTtl.toSeconds(), sessionId, roles);
    }

    public String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
