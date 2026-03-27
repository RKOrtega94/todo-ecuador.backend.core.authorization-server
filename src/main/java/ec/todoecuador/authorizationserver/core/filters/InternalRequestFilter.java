package ec.todoecuador.authorizationserver.core.filters;

import ec.todoecuador.authorizationserver.core.properties.AppProperties;
import ec.todoecuador.authorizationserver.core.validators.EurekaServiceValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InternalRequestFilter extends OncePerRequestFilter {
    private static final String INTERNAL_PATH = "/internal/token";
    private static final String INTERNAL_HEADER = "X-Internal-Request";

    private final AppProperties props;
    private final EurekaServiceValidator serviceValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
//        if (!request.getRequestURI().equals(INTERNAL_PATH)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//        var clientIp = resolveClientIp(request);
//        var secret = request.getHeader(INTERNAL_HEADER);
//        if (!serviceValidator.isCallerAllowed(clientIp)) {
//            log.warn("Unauthorized internal request from IP: {}", clientIp);
//            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
//            return;
//        }
//        if (!props.getInternal().getSecret().equals(secret)) {
//            log.warn("Invalid internal request secret from IP: {}", clientIp);
//            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
//            return;
//        }
        filterChain.doFilter(request, response);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : request.getRemoteAddr();
    }
}