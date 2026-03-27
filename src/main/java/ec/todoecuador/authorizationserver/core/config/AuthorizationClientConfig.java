package ec.todoecuador.authorizationserver.core.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Duration;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationClientConfig {
    private final JdbcTemplate jdbcTemplate;

    @Value("${oauth2.client.oidc.id:default}")
    private String clientId;

    @Value("${oauth2.client.oidc.secret:secret}")
    private String clientSecret;

    @Value("${oauth2.client.gateway.id:todo-ecuador-id}")
    private String gatewayClientId;

    @Value("${oauth2.client.gateway.secret:todo-ecuador-secret}")
    private String gatewayClientSecret;

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // API Client (Internal — client credentials)
        RegisteredClient apiClient = repository.findByClientId(clientId);
        if (apiClient == null) {
            repository.save(buildApiClient(UUID.randomUUID().toString(), passwordEncoder));
        }

        // Gateway Client (Public — authorization code + refresh token with rotation)
        RegisteredClient gatewayClient = repository.findByClientId(gatewayClientId);
        if (gatewayClient == null) {
            repository.save(buildGatewayClient(UUID.randomUUID().toString(), passwordEncoder));
        }

        return repository;
    }

    private RegisteredClient buildApiClient(String id, PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("api.read")
                .scope("api.write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .build())
                .build();
    }

    private RegisteredClient buildGatewayClient(String id, PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(id)
                .clientId(gatewayClientId)
                .clientSecret(passwordEncoder.encode(gatewayClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/login/oauth2/code/todo-ecuador-client")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("api.read")
                .scope("api.write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofHours(24))
                        // Refresh token rotation: a new refresh token is issued on every use; the old one is invalidated
                        .reuseRefreshTokens(false)
                        .build())
                .build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * Customizer for the standard OAuth2 token endpoint flow (authorization code / client credentials).
     * Injects a {@code jti} claim that can be used for revocation tracking.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            JwtClaimsSet.Builder claims = context.getClaims();
            // Ensure every JWT issued via the standard /oauth2/token endpoint carries a unique JTI
            claims.id(UUID.randomUUID().toString());
        };
    }

    /**
     * Shared {@link JwtEncoder} used by both the standard Authorization Server token endpoint
     * and the custom REST token issuance service ({@code TokenIssuanceService}).
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
