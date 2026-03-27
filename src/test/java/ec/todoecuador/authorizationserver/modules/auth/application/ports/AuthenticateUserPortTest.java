package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.application.service.TokenIssuanceService;
import ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities.UserForeignEntity;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.UserRepository;
import ec.todoecuador.common.i18n.MessageResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticateUserPortTest {

    private static final String USERNAME = "john";
    private static final String PASSWORD = "secret";
    private static final DeviceContext DEVICE = new DeviceContext("dev-1", "Test Device", "JUnit/5", "127.0.0.1");

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private UserRepository userRepository;
    @Mock
    private TokenIssuanceService tokenIssuanceService;
    @Mock
    private MessageResolver messageResolver;

    private AuthenticateUserPort authenticateUserPort;
    private Clock fixedClock;

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(Instant.parse("2026-03-14T12:00:00Z"), ZoneOffset.UTC);
        authenticateUserPort = new AuthenticateUserPort(authenticationManager, userRepository, tokenIssuanceService, fixedClock, messageResolver);
    }

    @Test
    void executeReturnsTokenPairWhenCredentialsAndUserStateAreValid() {
        UserForeignEntity user = validUser();
        Authentication expectedAuth = UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, List.of());
        TokenPair expectedTokenPair = new TokenPair("access", "refresh", "Bearer", 1800L, UUID.randomUUID(), Collections.emptyList());

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(expectedAuth);
        when(tokenIssuanceService.issue(any(Authentication.class), any(DeviceContext.class))).thenReturn(expectedTokenPair);

        TokenPair actual = authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE);

        assertEquals(expectedTokenPair, actual);
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(tokenIssuanceService).issue(any(Authentication.class), eq(DEVICE));
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsNotFound() {
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE));

        verify(authenticationManager, never()).authenticate(any());
        verify(tokenIssuanceService, never()).issue((Authentication) any(), any());
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsDisabled() {
        UserForeignEntity user = validUser();
        user.setEnabled(false);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE));

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsLocked() {
        UserForeignEntity user = validUser();
        user.setLocked(true);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE));

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void executeThrowsBadCredentialsWhenPasswordExpirationEqualsNow() {
        UserForeignEntity user = validUser();
        user.setPasswordExpiration(Instant.now(fixedClock));
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE));

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void executeThrowsBadCredentialsWhenAuthenticationManagerFails() {
        UserForeignEntity user = validUser();
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("bad"));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD, DEVICE));

        verify(tokenIssuanceService, never()).issue((Authentication) any(), any());
    }

    private UserForeignEntity validUser() {
        UserForeignEntity user = new UserForeignEntity();
        user.setUsername(USERNAME);
        user.setEnabled(true);
        user.setLocked(false);
        user.setPasswordExpiration(Instant.parse("2026-03-15T12:00:00Z"));
        return user;
    }
}
