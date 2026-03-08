package ec.todoecuador.authorizationserver.core.keystore;

import ec.todoecuador.authorizationserver.core.properties.KeystoreProperties;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeystoreBootstrapService {
    private final KeystoreProperties props;
    private final KeystoreSecretManager secretManager;
    private final ApplicationEventPublisher publisher;

    @PostConstruct
    public void ensureKeystoreExists() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, OperatorCreationException {
        Path ksPath = props.keystorePath();
        Files.createDirectories(ksPath.getParent());
        if (!Files.exists(ksPath)) {
            log.info("Creating keystore at {}", ksPath);
            createKeystore(ksPath);
            log.info("Keystore created successfully");
        } else {
            log.info("Keystore already exists at {}", ksPath);
            validateIntegrity(ksPath);
        }
    }

    public KeystoreResult createKeystore(Path targetPath) throws IOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, KeyStoreException {
        char[] password = secretManager.getOrCreateSecret();
        KeyPair keyPair = generateRSAKeyPair();
        X509Certificate cert = generateCertificate(keyPair);
        saveKeyStore(keyPair.getPrivate(), cert, targetPath, password);
        log.info("Keystore created -> alias: {}, expires: {}", props.getAlias(), cert.getNotAfter());
        publisher.publishEvent(new KeystoreCreatedEvent(this, cert, targetPath));
        return new KeystoreResult(cert.getNotAfter().toInstant(), targetPath);
    }

    KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    X509Certificate generateCertificate(KeyPair keyPair) throws CertIOException, CertificateException, OperatorCreationException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + TimeUnit.DAYS.toMillis(props.getValidityDays()));
        X500Name subject = new X500Name(String.format("CN=%s, OU=Dev, O=MyOrg, C=US", props.getAlias()));
        BigInteger serial = BigInteger.valueOf(now);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serial, startDate, endDate, subject, keyPair.getPublic());
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    void saveKeyStore(PrivateKey privateKey, X509Certificate certificate, Path targetPath, char[] password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(props.getAlias(), privateKey, password, new java.security.cert.Certificate[]{certificate});
        Files.createDirectories(targetPath.getParent());
        try (var out = Files.newOutputStream(targetPath)) {
            ks.store(out, password);
        }
    }

    private void validateIntegrity(Path ksPath) {
        try {
            char[] password = secretManager.getOrCreateSecret();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(ksPath)) {
                ks.load(in, password);
            } catch (CertificateException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            log.info("Keystore integrity validated");
        } catch (IOException | KeyStoreException e) {
            log.error("Failed to validate keystore integrity", e);
            throw new RuntimeException(e);
        }
    }

    public record KeystoreResult(Instant expiresAt, Path path) {
    }

    public static class KeystoreCreatedEvent extends ApplicationEvent {
        @Getter
        private final X509Certificate certificate;
        @Getter
        private final Path ksPath;

        public KeystoreCreatedEvent(Object source, X509Certificate certificate, Path ksPath) {
            super(source);
            this.certificate = certificate;
            this.ksPath = ksPath;
        }
    }
}
