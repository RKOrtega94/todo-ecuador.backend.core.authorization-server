package ec.todoecuador.authorizationserver.modules.auth.application.ports;

import ec.todoecuador.authorizationserver.modules.auth.application.service.TokenIssuanceService;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.GenerateProvisionalTokenUseCase;
import ec.todoecuador.common.dtos.requests.InternalTokenRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GenerateProvisionalTokenPort implements GenerateProvisionalTokenUseCase {
    private final AuthenticationManager authenticationManager;
    private final TokenIssuanceService tokenService;

    @Override
    public TokenPair execute(InternalTokenRequest request, DeviceContext device) {
        return tokenService.issue(request, device);
    }
}
