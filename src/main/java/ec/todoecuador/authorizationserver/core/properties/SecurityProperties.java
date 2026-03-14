package ec.todoecuador.authorizationserver.core.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.server")
public class SecurityProperties {
    private String issuer = "http://localhost:8080";
    private Integer maxSessionsPerUser = 3;
}
