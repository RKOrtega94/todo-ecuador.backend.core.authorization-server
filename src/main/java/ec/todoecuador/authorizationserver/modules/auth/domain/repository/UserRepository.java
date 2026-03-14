package ec.todoecuador.authorizationserver.modules.auth.domain.repository;

import ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities.UserForeignEntity;

import java.util.Optional;

public interface UserRepository {
    Optional<UserForeignEntity> findByUsername(String username);
}
