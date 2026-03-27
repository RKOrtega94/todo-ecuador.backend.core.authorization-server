package ec.todoecuador.authorizationserver.modules.auth.application.utils;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import jakarta.servlet.http.HttpServletRequest;

public class RequestUtils {
    private RequestUtils() {
    }

    private static final String HEADER_X_DEVICE_ID = "X-Device-Id";
    private static final String HEADER_X_DEVICE_NAME = "X-Device-Name";

    public static DeviceContext extractDeviceContext(HttpServletRequest request) {
        String deviceId = request.getHeader(HEADER_X_DEVICE_ID);
        String deviceName = request.getHeader(HEADER_X_DEVICE_NAME);
        String userAgent = request.getHeader("User-Agent");
        String ipAddress = extractClientIp(request);

        if (deviceId == null || deviceId.isBlank()) {
            return DeviceContext.unknown(userAgent, ipAddress);
        }
        return new DeviceContext(deviceId, deviceName, userAgent, ipAddress);
    }

    private static String extractClientIp(HttpServletRequest request) {
        return getXForwarded(request);
    }

    public static String getXForwarded(HttpServletRequest request) {
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
}
