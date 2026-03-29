package ec.todoecuador.authorizationserver.modules.auth.application.service;

import ec.todoecuador.authorizationserver.core.properties.SecurityProperties;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.AuthSession;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.AuthSessionRepository;
import ec.todoecuador.common.dtos.requests.InternalTokenRequest;
import ec.todoecuador.common.i18n.MessageResolver;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core service responsible for issuing JWT access tokens and opaque refresh tokens,
 * persisting sessions with device metadata, and enforcing the maximum-sessions-per-user policy
 * by evicting the oldest active session when the limit is reached.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenIssuanceService {
    private static final int PROVISIONAL_MAX_SESSIONS = 1;
    private static final String TOKEN_TYPE = "Bearer";

    private final JwtEncoder jwtEncoder;
    private final AuthSessionRepository authSessionRepository;
    private final SecurityProperties securityProperties;
    private final MessageResolver messageResolver;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public TokenPair issue(Authentication authentication, DeviceContext device) {
        String username = authentication.getName();
        Set<String> authorities = extractAuthorities(authentication);
        enforceSessionLimit(username, securityProperties.getMaxSessionsPerUser());
        return buildTokenPair(username, authorities, Duration.ofMinutes(securityProperties.getAccessTokenTtlMinutes()), Duration.ofHours(securityProperties.getRefreshTokenTtlHours()), device, null);
    }

    @Transactional
    public TokenPair issue(InternalTokenRequest request, DeviceContext context) {
        String username = request.subject();
        Map<String, Object> claims = request.claims();
        Set<String> authorities = request.authorities();
        enforceSessionLimit(username, PROVISIONAL_MAX_SESSIONS);
        return buildTokenPair(username, authorities, Duration.ofMinutes(securityProperties.getAccessTokenTtlMinutes()), Duration.ofHours(securityProperties.getRefreshTokenTtlHours()), context, claims);
    }

    private TokenPair buildTokenPair(String subject, Set<String> authorities, Duration accessTtl, Duration refreshTtl, DeviceContext device, Map<String, Object> customClaims) {
        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();
        UUID sessionId = UUID.randomUUID();

        // Build JWT Claims
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder().issuer(securityProperties.getIssuer()).issuedAt(now).expiresAt(now.plus(accessTtl)).subject(subject).id(jti).claim("session_id", sessionId.toString()).claim("device_id", device.deviceId()).claim("authorities", authorities);

        if (customClaims != null && !customClaims.isEmpty()) {
            customClaims.forEach(claimsBuilder::claim);
        }

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claimsBuilder.build()));

        String rawRefreshToken = generateOpaqueToken();
        String refreshTokenHash = hashToken(rawRefreshToken);

        AuthSession.AuthSessionBuilder session = AuthSession.builder();
        session.id(sessionId);
        session.username(subject);
        session.deviceId(device.deviceId());
        session.deviceName(device.deviceName());
        session.userAgent(device.userAgent());
        session.ipAddress(device.ipAddress());
        session.accessTokenJti(jti);
        session.refreshTokenHash(refreshTokenHash);
        session.createdAt(now);
        session.lastSeenAt(now);
        session.expiresAt(now.plus(refreshTtl));

        var authSession = session.build();
        authSessionRepository.save(authSession);

        return TokenPair.builder().accessToken(jwt.getTokenValue()).refreshToken(rawRefreshToken).tokenType(TOKEN_TYPE).expiresIn(accessTtl.toSeconds()).sessionId(sessionId).build();
    }

    public String hashToken(String rawRefreshToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawRefreshToken.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available for hashing refresh tokens. This is required for security.", e);
        }
    }

    private String generateOpaqueToken() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }

    private void enforceSessionLimit(String username, Integer maxSessionsPerUser) {
        long activeSessions = authSessionRepository.countActiveSessionsByUsername(username);
        if (activeSessions >= maxSessionsPerUser) authSessionRepository.deleteOldestSessionByUsername(username);

    }

    private Set<String> extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(Objects::nonNull).map(a -> a.toUpperCase().startsWith("ROLE_") ? a.substring(5).toUpperCase() : a.toUpperCase()).collect(Collectors.toSet());
    }
}
