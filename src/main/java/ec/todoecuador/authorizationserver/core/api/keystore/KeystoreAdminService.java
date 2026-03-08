package ec.todoecuador.authorizationserver.core.api.keystore;

import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Service;

import ec.todoecuador.authorizationserver.core.keystore.KeystoreRotationService;
import ec.todoecuador.authorizationserver.core.keystore.KeystoreSecretManager;
import ec.todoecuador.authorizationserver.core.properties.KeystoreProperties;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class KeystoreAdminService {
    private final KeystoreProperties props;
    private final KeystoreSecretManager secretManager;
    private final KeystoreRotationService rotationService;

    private final AtomicReference<RotationStatusResponse> lastRotation = new AtomicReference<>();

    public KeystoreInfoResponse getInfo() {
        X509Certificate certificate = readCertificate();
        Instant expiresAt = certificate.getNotAfter().toInstant();
        long daysUntilExpiry = Duration.between(Instant.now(), expiresAt).toDays();
        boolean backupAvailable = Files.exists(props.backUpPath());

        return new KeystoreInfoResponse(
                props.getAlias(),
                props.keystorePath().toString(),
                expiresAt,
                daysUntilExpiry,
                backupAvailable
        );
    }

    public RotationStatusResponse rotate() {
        KeystoreRotationService.RotationResult result = rotationService.rotate();
        RotationStatusResponse status = new RotationStatusResponse(
                Boolean.TRUE.equals(result.success()),
                result.expiresAt(),
                result.message(),
                Instant.now()
        );
        lastRotation.set(status);
        return status;
    }

    public RotationStatusResponse getLastRotationStatus() {
        RotationStatusResponse status = lastRotation.get();
        if (status != null) {
            return status;
        }

        KeystoreInfoResponse info = getInfo();
        return new RotationStatusResponse(
                true,
                info.expiresAt(),
                "No rotation executed since startup",
                null
        );
    }

    private X509Certificate readCertificate() {
        try {
            char[] password = secretManager.getOrCreateSecret();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(props.keystorePath())) {
                keyStore.load(in, password);
            }

            if (!keyStore.containsAlias(props.getAlias())) {
                throw new IllegalStateException("Alias not found in keystore: " + props.getAlias());
            }

            return (X509Certificate) keyStore.getCertificate(props.getAlias());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | java.io.IOException e) {
            throw new IllegalStateException("Failed to read keystore certificate", e);
        }
    }
}
