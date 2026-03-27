package ec.todoecuador.authorizationserver.core.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ec.todoecuador.authorizationserver.core.jwk_sorce.JwkSourceManager;
import ec.todoecuador.authorizationserver.core.properties.SecurityProperties;
import ec.todoecuador.authorizationserver.core.security.RateLimitingFilter;
import ec.todoecuador.authorizationserver.core.security.TokenRevocationLogoutHandler;
import ec.todoecuador.authorizationserver.core.security.TokenRevocationValidator;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.RevokeTokenUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import java.time.Clock;
import java.util.Optional;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationSecurityConfig {

    private final SecurityProperties securityProperties;
    private final SpringSessionBackedSessionRegistry<? extends Session> sessionRegistry;
    private final TokenRevocationValidator tokenRevocationValidator;
    private final RevokeTokenUseCase revokeTokenUseCase;

    /**
     * Optional: only wired when rate limiting is enabled (conditional bean).
     */
    @Autowired(required = false)
    private RateLimitingFilter rateLimitingFilter;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) {
        http.oauth2AuthorizationServer(authServer -> {
            http.securityMatcher(authServer.getEndpointsMatcher());
            authServer.oidc(Customizer.withDefaults());
        }).csrf(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable).logout(logout -> logout.logoutUrl("/api/v1/auth/logout").addLogoutHandler(new TokenRevocationLogoutHandler(revokeTokenUseCase)).logoutSuccessHandler((request, response, authentication) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write("{ \"message\": \"Logout successful\" }");
        })).sessionManagement(session -> session.maximumSessions(securityProperties.getMaxSessionsPerUser()).sessionRegistry(sessionRegistry)).authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/auth/login").permitAll().requestMatchers("/api/v1/auth/refresh").permitAll().requestMatchers("/internal/token").permitAll().anyRequest().authenticated()).exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, authException) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getOutputStream().println("{ \"error\": \"" + authException.getMessage() + "\" }");
        }).accessDeniedHandler((request, response, accessDeniedException) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getOutputStream().println("{ \"error\": \"Access denied: " + accessDeniedException.getMessage() + "\" }");
        })).oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.decoder(jwtDecoder(null))));

        addRateLimitingFilter(http);
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable).logout(logout -> logout.logoutUrl("/api/v1/auth/logout").addLogoutHandler(new TokenRevocationLogoutHandler(revokeTokenUseCase)).logoutSuccessHandler((request, response, authentication) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write("{ \"message\": \"Logout successful\" }");
        })).sessionManagement(session -> session.maximumSessions(securityProperties.getMaxSessionsPerUser()).sessionRegistry(sessionRegistry)).authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/auth/login").permitAll().requestMatchers("/api/v1/auth/refresh").permitAll().requestMatchers("/internal/token").permitAll().requestMatchers("/api/v1/admin/**").hasRole("ADMIN").anyRequest().authenticated()).exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, authException) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getOutputStream().println("{ \"error\": \"" + authException.getMessage() + "\" }");
        }).accessDeniedHandler((request, response, accessDeniedException) -> {
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getOutputStream().println("{ \"error\": \"Access denied: " + accessDeniedException.getMessage() + "\" }");
        })).oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.decoder(jwtDecoder(null))));

        addRateLimitingFilter(http);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JwkSourceManager manager) {
        return manager.getCombinedSource();
    }

    /**
     * JwtDecoder wired with:
     * - Default expiry / issuer validators
     * - Custom {@link TokenRevocationValidator} that rejects revoked tokens by JTI
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // jwkSource may be null during early bean resolution; use a lazy approach
        JWKSource<SecurityContext> source = Optional.ofNullable(jwkSource).orElseThrow(() -> new IllegalStateException("JWKSource must be available"));

        var jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
        var selector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source);
        jwtProcessor.setJWSKeySelector(selector);

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(securityProperties.getIssuer()), tokenRevocationValidator));

        return decoder;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    private void addRateLimitingFilter(HttpSecurity http) {
        if (rateLimitingFilter != null) {
            http.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);
        }
    }
}
