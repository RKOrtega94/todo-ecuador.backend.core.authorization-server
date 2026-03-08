package ec.todoecuador.authorizationserver.core.keystore;

import ec.todoecuador.authorizationserver.core.properties.KeystoreProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeystoreSecretManager {
    private final KeystoreProperties props;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicReference<char[]> secret = new AtomicReference<>();

    public synchronized char[] getOrCreateSecret() throws IOException {
        if (secret.get() != null) return secret.get();

        Path passwordFile = props.passwordFile();
        if (Files.exists(passwordFile)) {
            var raw = Files.readString(passwordFile).trim();
            secret.set(raw.toCharArray());
        } else {
            secret.set(generateSecureSecret());
            persistSecret(passwordFile, new String(secret.get()));
        }
        return secret.get();
    }

    public void clearCache() {
        if (secret.get() != null) {
            Arrays.fill(secret.get(), '\0');
            secret.set(null);
        }
    }

    private char[] generateSecureSecret() {
        byte[] secureSecret = new byte[32];
        secureRandom.nextBytes(secureSecret);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(secureSecret).toCharArray();
    }

    private void persistSecret(Path passwordFile, String secret) throws IOException {
        Files.createDirectories(passwordFile.getParent());
        Files.writeString(passwordFile, secret, StandardOpenOption.CREATE_NEW);
        try {
            Set<PosixFilePermission> perms = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(passwordFile, perms);
        } catch (UnsupportedOperationException e) {
            log.warn("Failed to set permissions on keystore password file: {}", e.getMessage());
        }
    }
}
