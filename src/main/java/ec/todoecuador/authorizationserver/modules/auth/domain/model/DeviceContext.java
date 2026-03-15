package ec.todoecuador.authorizationserver.modules.auth.domain.model;

/**
 * Contextual information about the client device that initiated an authentication request.
 * Used for session tracking, device identification and suspicious activity detection.
 */
public record DeviceContext(
        String deviceId,
        String deviceName,
        String userAgent,
        String ipAddress) {

    /** Fallback device ID when the client does not supply an X-Device-Id header. */
    public static DeviceContext unknown(String userAgent, String ipAddress) {
        return new DeviceContext("unknown-" + ipAddress, "Unknown Device", userAgent, ipAddress);
    }
}
