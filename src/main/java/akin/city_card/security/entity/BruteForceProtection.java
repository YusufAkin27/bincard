package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "brute_force_protection",
        indexes = {
                @Index(name = "idx_bf_identifier", columnList = "identifier"),
                @Index(name = "idx_bf_locked_until", columnList = "lockedUntil"),
                @Index(name = "idx_bf_last_attempt", columnList = "lastAttemptTime")
        })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BruteForceProtection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String identifier; // username, email, phone

    @Builder.Default
    private int failedAttempts = 0;

    private LocalDateTime lastAttemptTime;

    private LocalDateTime lockedUntil;

    private LocalDateTime lastSuccessfulLogin;

    @Column(length = 45)
    private String lastIpAddress;

    @Column(length = 500)
    private String lastUserAgent;

    @Column(length = 500)
    private String lockReason;

    @CreationTimestamp
    private LocalDateTime createdAt;

    public boolean isCurrentlyLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public long getRemainingLockMinutes() {
        if (!isCurrentlyLocked()) {
            return 0;
        }
        return java.time.Duration.between(LocalDateTime.now(), lockedUntil).toMinutes();
    }
}