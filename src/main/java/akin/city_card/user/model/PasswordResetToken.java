package akin.city_card.user.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class PasswordResetToken {
    @Id
    @GeneratedValue
    private Long id;

    private String token;

    private LocalDateTime expiresAt;

    private boolean used;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser user;
}
