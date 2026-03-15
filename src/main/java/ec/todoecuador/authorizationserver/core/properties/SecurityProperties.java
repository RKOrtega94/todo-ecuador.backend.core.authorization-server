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

    /** Access token time-to-live in minutes. */
    private Integer accessTokenTtlMinutes = 30;

    /** Refresh token time-to-live in hours. */
    private Integer refreshTokenTtlHours = 24;

    private RateLimit rateLimit = new RateLimit();

    @Data
    public static class RateLimit {
        /** Enable distributed Redis-backed rate limiting for auth endpoints. */
        private boolean enabled = false;
        /** Max login requests per IP per window. */
        private int loginMaxRequests = 10;
        /** Max refresh requests per IP per window. */
        private int refreshMaxRequests = 20;
        /** Sliding window duration in seconds. */
        private int windowSeconds = 60;
    }
}
