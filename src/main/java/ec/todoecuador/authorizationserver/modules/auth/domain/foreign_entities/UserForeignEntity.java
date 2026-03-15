package ec.todoecuador.authorizationserver.modules.auth.domain.foreign_entities;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class UserForeignEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    private String username;
    private String password;
    @Column(name = "password_expiration")
    private Instant passwordExpiration;
    @ColumnDefault("false")
    @Column(name = "verified")
    private Boolean verified;
    @ColumnDefault("false")
    @Column(name = "locked")
    private Boolean locked;
    @ColumnDefault("true")
    @Column(name = "enabled")
    private Boolean enabled;

    @Builder.Default
    @ManyToMany
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleForeignEntity> roles = new HashSet<>();
}