package ec.todoecuador.authorizationserver.core.security;

import ec.todoecuador.authorizationserver.core.properties.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * Distributed rate limiting filter backed by Redis.
 * Applies a fixed-window counter per client IP for sensitive authentication endpoints.
 * Only active when {@code auth.server.rate-limit.enabled=true} and a Redis connection is available.
 *
 * <p>Fail-open: if Redis is unavailable the request is allowed through to preserve availability.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.server.rate-limit", name = "enabled", havingValue = "true")
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final String RATE_LIMIT_KEY_PREFIX = "rl:auth:";
    private static final String HEADER_RETRY_AFTER = "Retry-After";
    private static final String HEADER_X_DEVICE_ID  = "X-Device-Id";

    /** Maps endpoint path → max requests per window. */
    private static final Map<String, String> ENDPOINT_LIMIT_CONFIG = Map.of(
            "/api/v1/auth/login",   "login",
            "/api/v1/auth/refresh", "refresh"
    );

    private final StringRedisTemplate redis;
    private final SecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();
        String limitKey = ENDPOINT_LIMIT_CONFIG.get(uri);

        if (limitKey == null) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityProperties.RateLimit cfg = securityProperties.getRateLimit();
        int maxRequests = "login".equals(limitKey) ? cfg.getLoginMaxRequests() : cfg.getRefreshMaxRequests();
        int windowSecs  = cfg.getWindowSeconds();

        String clientKey = buildClientKey(request, uri);

        try {
            Long count = redis.opsForValue().increment(clientKey);
            if (count != null && count == 1L) {
                redis.expire(clientKey, Duration.ofSeconds(windowSecs));
            }
            if (count != null && count > maxRequests) {
                log.warn("Rate limit exceeded for key='{}', count={}", clientKey, count);
                writeTooManyRequests(response, windowSecs);
                return;
            }
        } catch (Exception e) {
            // Fail-open: Redis unavailable — allow the request but log a warning
            log.warn("Rate limiting Redis error (fail-open): {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String buildClientKey(HttpServletRequest request, String uri) {
        String ip       = extractClientIp(request);
        String deviceId = request.getHeader(HEADER_X_DEVICE_ID);
        if (deviceId != null && !deviceId.isBlank()) {
            return RATE_LIMIT_KEY_PREFIX + uri + ":" + ip + ":" + deviceId;
        }
        return RATE_LIMIT_KEY_PREFIX + uri + ":" + ip;
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp;
        }
        return request.getRemoteAddr();
    }

    private void writeTooManyRequests(HttpServletResponse response, int retryAfter) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.addHeader(HEADER_RETRY_AFTER, String.valueOf(retryAfter));
        response.getWriter().write("{\"error\":\"Too many requests\",\"retryAfter\":" + retryAfter + "}");
    }
}
