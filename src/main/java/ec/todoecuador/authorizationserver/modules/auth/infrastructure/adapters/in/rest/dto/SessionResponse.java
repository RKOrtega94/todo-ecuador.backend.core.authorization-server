package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.ActiveSession;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
public class SessionResponse {
    private UUID id;
    private String deviceId;
    private String deviceName;
    private String userAgent;
    private String ipAddress;
    private Instant createdAt;
    private Instant lastSeenAt;
    private boolean current;

    public static SessionResponse from(ActiveSession session) {
        return SessionResponse.builder()
                .id(session.id())
                .deviceId(session.deviceId())
                .deviceName(session.deviceName())
                .userAgent(session.userAgent())
                .ipAddress(session.ipAddress())
                .createdAt(session.createdAt())
                .lastSeenAt(session.lastSeenAt())
                .current(session.current())
                .build();
    }
}
