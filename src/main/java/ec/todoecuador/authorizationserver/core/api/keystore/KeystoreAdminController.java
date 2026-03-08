package ec.todoecuador.authorizationserver.core.api.keystore;

import ec.todoecuador.common.http.CustomApiResponse;
import ec.todoecuador.common.http.CustomSuccessResponse;
import ec.todoecuador.common.i18n.I18nKeys;
import ec.todoecuador.common.i18n.MessageResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin/keystore")
public class KeystoreAdminController {
    private final KeystoreAdminService service;
    private final MessageResolver messageResolver;

    @GetMapping("/info")
    public ResponseEntity<CustomApiResponse> getInfo() {
        KeystoreInfoResponse response = service.getInfo();
        return ResponseEntity.ok(CustomSuccessResponse.ok(messageResolver.get(I18nKeys.KEYSTORE_INFO_RETRIEVED), response));
    }

    @PostMapping("/rotate")
    public ResponseEntity<CustomApiResponse> rotate() {
        RotationStatusResponse response = service.rotate();
        return ResponseEntity.ok(CustomSuccessResponse.ok(messageResolver.get(I18nKeys.KEYSTORE_ROTATED), response));
    }

    @GetMapping("/rotation-status")
    public ResponseEntity<CustomApiResponse> getRotationStatus() {
        RotationStatusResponse response = service.getLastRotationStatus();
        return ResponseEntity.ok(CustomSuccessResponse.ok(messageResolver.get(I18nKeys.KEYSTORE_ROTATION_STATUS), response));
    }
}
