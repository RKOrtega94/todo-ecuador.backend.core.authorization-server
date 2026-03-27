package ec.todoecuador.authorizationserver.core.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private Internal internal = new Internal();

    @Data
    public static class Internal {
        private String secret;
        private List<String> allowedServices = new ArrayList<>();
    }
}
