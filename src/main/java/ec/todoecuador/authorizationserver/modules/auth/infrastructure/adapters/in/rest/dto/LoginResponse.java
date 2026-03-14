package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private String username;
    private String message;
}
