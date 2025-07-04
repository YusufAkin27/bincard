package akin.city_card.verification.model;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 6)
    private String code;

    @Column(nullable = false)
    private boolean used = false;

    @Column(nullable = false)
    private boolean cancelled = false; // 5 hatalı denemeden sonra true olacak

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private VerificationChannel channel; // EMAIL / SMS

    private LocalDateTime verifiedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private VerificationPurpose purpose; // REGISTER, LOGIN, etc.

    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(length = 50)
    private String ipAddress;

    @Column(length = 255)
    private String userAgent;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser user;
}
