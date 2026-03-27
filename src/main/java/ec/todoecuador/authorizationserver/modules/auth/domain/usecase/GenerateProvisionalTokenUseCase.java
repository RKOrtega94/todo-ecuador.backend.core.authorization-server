package ec.todoecuador.authorizationserver.modules.auth.domain.usecase;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.DeviceContext;
import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.common.dtos.requests.InternalTokenRequest;

public interface GenerateProvisionalTokenUseCase {
    TokenPair execute(InternalTokenRequest request, DeviceContext device);
}
