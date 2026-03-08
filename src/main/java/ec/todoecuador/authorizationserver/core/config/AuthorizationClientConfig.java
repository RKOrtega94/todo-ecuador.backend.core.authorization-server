package ec.todoecuador.authorizationserver.core.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

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

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        RegisteredClient registeredClient = repository.findByClientId(clientId);
        if (registeredClient == null) {
            repository.save(buildApiClient(UUID.randomUUID().toString(), passwordEncoder));
        } else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
            repository.save(buildApiClient(registeredClient.getId(), passwordEncoder));
        }
        return repository;
    }

        private RegisteredClient buildApiClient(String id, PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(id) //
            .clientId(clientId) //
            .clientSecret(passwordEncoder.encode(clientSecret)) //
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) //
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) //
            .scope("api.read") //
            .scope("api.write") //
            .clientSettings(ClientSettings.builder() //
                .requireAuthorizationConsent(false) // API-only, no UI consent flow
                .requireProofKey(false) // PKCE applies to browser-based flows
                .build()) //
            .tokenSettings(TokenSettings.builder() //
                .accessTokenTimeToLive(Duration.ofMinutes(30)) //
                .build()) //
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
}
