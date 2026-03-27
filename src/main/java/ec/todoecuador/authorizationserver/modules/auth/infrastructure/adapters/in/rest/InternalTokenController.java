package ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest;

import ec.todoecuador.authorizationserver.modules.auth.domain.model.TokenPair;
import ec.todoecuador.authorizationserver.modules.auth.domain.usecase.GenerateProvisionalTokenUseCase;
import ec.todoecuador.authorizationserver.modules.auth.infrastructure.adapters.in.rest.dto.TokenResponse;
import ec.todoecuador.common.dtos.requests.InternalTokenRequest;
import ec.todoecuador.common.http.CustomApiResponse;
import ec.todoecuador.common.http.CustomSuccessResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static ec.todoecuador.authorizationserver.modules.auth.application.utils.RequestUtils.extractDeviceContext;

@Slf4j
@RestController
@RequestMapping("/internal/token")
@RequiredArgsConstructor
public class InternalTokenController {
    private final GenerateProvisionalTokenUseCase generateProvisional;

    @PostMapping
    public ResponseEntity<CustomApiResponse> authenticateInternal(@RequestBody @Valid InternalTokenRequest tokenRequest, HttpServletRequest request) {
        var device = extractDeviceContext(request);
        TokenPair response = generateProvisional.execute(tokenRequest, device);
        return ResponseEntity.ok(CustomSuccessResponse.ok(TokenResponse.from(response)));
    }
}