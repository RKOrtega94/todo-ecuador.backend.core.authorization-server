package ec.todoecuador.authorizationserver.core.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

@Data
@Component
@ConfigurationProperties(prefix = "app.keystore")
public class KeystoreProperties {
    private String dir = "keystore";
    private String alias = "keystore_alias";
    private Integer validityDays = 365;
    private Integer renewalThresholdDays = 30;
    private Integer overlapDays = 7;

    public Path keystorePath() {
        return Path.of(dir, String.format("%s.p12", alias));
    }

    public Path backUpPath() {
        return Path.of(dir, String.format("%s.p12.bak", alias));
    }

    public Path passwordFile() {
        return Path.of(dir, String.format("%s.secret", alias));
    }
}
