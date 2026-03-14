package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities.UserForeignEntity;
import ec.todoecuador.authorizationserver.modules.auth.domain.repository.UserRepository;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticateUserPortTest {

    private static final String USERNAME = "john";
    private static final String PASSWORD = "secret";

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    private AuthenticateUserPort authenticateUserPort;

    private Clock fixedClock;

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(Instant.parse("2026-03-14T12:00:00Z"), ZoneOffset.UTC);
        authenticateUserPort = new AuthenticateUserPort(authenticationManager, userRepository, fixedClock);
    }

    @Test
    void executeReturnsAuthenticationWhenCredentialsAndUserStateAreValid() {
        UserForeignEntity user = validUser();
        Authentication expectedAuthentication =
                UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, java.util.List.of());

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(expectedAuthentication);

        Authentication actual = authenticateUserPort.execute(USERNAME, PASSWORD);

        assertEquals(expectedAuthentication, actual);
        verify(authenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsNotFound() {
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD));

        verify(authenticationManager, never()).authenticate(any(Authentication.class));
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsDisabled() {
        UserForeignEntity user = validUser();
        user.setEnabled(false);

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD));

        verify(authenticationManager, never()).authenticate(any(Authentication.class));
    }

    @Test
    void executeThrowsBadCredentialsWhenUserIsLocked() {
        UserForeignEntity user = validUser();
        user.setLocked(true);

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD));

        verify(authenticationManager, never()).authenticate(any(Authentication.class));
    }

    @Test
    void executeThrowsBadCredentialsWhenPasswordExpirationEqualsNow() {
        UserForeignEntity user = validUser();
        user.setPasswordExpiration(Instant.now(fixedClock));

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD));

        verify(authenticationManager, never()).authenticate(any(Authentication.class));
    }

    @Test
    void executeThrowsBadCredentialsWhenAuthenticationManagerFails() {
        UserForeignEntity user = validUser();

        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("bad"));

        assertThrows(BadCredentialsException.class, () -> authenticateUserPort.execute(USERNAME, PASSWORD));
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

