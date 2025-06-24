package akin.city_card.user.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
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

    @OneToOne
    private User user;
}
