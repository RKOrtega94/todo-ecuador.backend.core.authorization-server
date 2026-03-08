package ec.todoecuador.authorizationserver.core.jwk_sorce;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import ec.todoecuador.authorizationserver.core.keystore.KeystoreSecretManager;
import ec.todoecuador.authorizationserver.core.keystore.KeystoreBootstrapService;
import ec.todoecuador.authorizationserver.core.keystore.KeystoreRotationService;
import ec.todoecuador.authorizationserver.core.properties.KeystoreProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwkSourceManager {
    private final KeystoreProperties props;
    private final KeystoreSecretManager secretManager;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private volatile JWKSource<SecurityContext> activeSource;
    private volatile JWKSource<SecurityContext> backupSource;
    private volatile ScheduledFuture<?> backupCleanupTask;

    @PostConstruct
    public void init() throws Exception {
        this.activeSource = loadSource();
        log.info("JWKSource initialized");
    }

    @PreDestroy
    public void shutdown() {
        scheduler.shutdownNow();
    }

    public JWKSource<SecurityContext> getCombinedSource() {
        return (selector, ctx) -> {
            List<JWK> keys = new ArrayList<>();
            safeGet(activeSource, selector, ctx, keys);
            if (backupSource != null) {
                safeGet(backupSource, selector, ctx, keys);
            }
            return keys;
        };
    }

    @EventListener({
            KeystoreRotationService.KeystoreRotationEvent.class,
            KeystoreBootstrapService.KeystoreCreatedEvent.class
    })
    public synchronized void onKeystoreChanged(ApplicationEvent event) throws Exception {
        log.info("Reloading JWKSource after keystore change: {}", event.getClass().getSimpleName());
        backupSource = activeSource;
        activeSource = loadSource();
        log.info("JWKSource hot-reloaded");
        scheduleBackupCleanup();
    }

    private JWKSource<SecurityContext> loadSource() throws Exception {
        char[] password = secretManager.getOrCreateSecret();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream inputStream = Files.newInputStream(props.keystorePath())) {
            keyStore.load(inputStream, password);
        }

        RSAKey rsaKey = RSAKey.load(keyStore, props.getAlias(), password);
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private void safeGet(
            JWKSource<SecurityContext> source,
            JWKSelector selector,
            SecurityContext context,
            List<JWK> out
    ) {
        if (source == null) {
            return;
        }
        try {
            out.addAll(source.get(selector, context));
        } catch (Exception e) {
            log.warn("JWK fetch error: {}", e.getMessage());
        }
    }

    private synchronized void scheduleBackupCleanup() {
        if (backupCleanupTask != null && !backupCleanupTask.isDone()) {
            backupCleanupTask.cancel(false);
        }

        backupCleanupTask = scheduler.schedule(() -> {
            log.info("JWK overlap period ended, clearing backup source");
            this.backupSource = null;
        }, props.getOverlapDays(), TimeUnit.DAYS);
    }
}
