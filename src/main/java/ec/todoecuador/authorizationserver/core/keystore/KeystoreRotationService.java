package ec.todoecuador.authorizationserver.core.keystore;

import ec.todoecuador.authorizationserver.core.properties.KeystoreProperties;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeystoreRotationService {
    private final KeystoreProperties props;
    private final KeystoreSecretManager manager;
    private final KeystoreBootstrapService bootstrap;
    private final ApplicationEventPublisher publisher;

    public RotationResult rotate() {
        log.warn("♻️ Rotating keystore...");
        Path current = props.keystorePath();
        Path backup = props.backUpPath();
        try {
            if (Files.exists(current)) {
                Files.copy(current, backup, StandardCopyOption.REPLACE_EXISTING);
                log.info("Keystore backup created at {}", backup);
            }
            char[] password = manager.getOrCreateSecret();
            KeyPair kp = bootstrap.generateRSAKeyPair();
            X509Certificate cert = bootstrap.generateCertificate(kp);
            bootstrap.saveKeyStore(kp.getPrivate(), cert, current, password);
            log.info("✅ Keystore rotation completed successfully, new certificate expires at: {}", cert.getNotAfter());
            publisher.publishEvent(new KeystoreRotationEvent(this, cert));
            return RotationResult.success(cert.getNotAfter().toInstant());
        } catch (IOException | NoSuchAlgorithmException | CertificateException | OperatorCreationException |
                 KeyStoreException e) {
            log.error("⛔ Failed to create keystore backup", e);
            rollback(current, backup);
            return RotationResult.failure(e.getMessage());
        }
    }

    private void rollback(Path current, Path backup) {
        try {
            if (Files.exists(backup)) Files.copy(backup, current, StandardCopyOption.REPLACE_EXISTING);
            log.info("✅ Keystore rollback completed successfully");
        } catch (IOException e) {
            log.error("⛔ Failed to rollback keystore", e);
        }
    }

    public record RotationResult(Boolean success, Instant expiresAt, String message) {
        static RotationResult success(Instant expiresAt) {
            return new RotationResult(true, expiresAt, "Keystore rotation completed successfully");
        }

        static RotationResult failure(String message) {
            return new RotationResult(false, null, message);
        }
    }

    public static class KeystoreRotationEvent extends ApplicationEvent {
        @Getter
        private final X509Certificate certificate;

        public KeystoreRotationEvent(Object source, X509Certificate certificate) {
            super(source);
            this.certificate = certificate;
        }
    }
}
