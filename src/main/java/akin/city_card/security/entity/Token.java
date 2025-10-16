package akin.city_card.security.entity;

import akin.city_card.security.entity.enums.TokenType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Table(
        name = "token",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "tokenType"}),
        indexes = {
                @Index(name = "idx_token_value", columnList = "tokenValue"),
                @Index(name = "idx_token_jti", columnList = "jti"),
                @Index(name = "idx_token_expires_at", columnList = "expiresAt"),
                @Index(name = "idx_token_user_type", columnList = "user_id, tokenType")
        }
)
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2048, nullable = false) // JWT tokenlar uzun olabilir
    private String tokenValue;

    @Column(nullable = false, unique = true)
    private String jti; // JWT ID - Replay attack koruması için

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser securityUser;

    @Builder.Default
    private boolean isValid = true;

    @Column(nullable = false)
    private LocalDateTime issuedAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    private LocalDateTime lastUsedAt; // Token'ın son kullanım zamanı

    @Column(length = 45) // IPv6 için yeterli
    private String ipAddress;

    @Column(length = 500) // User-Agent uzun olabilir
    private String deviceInfo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType;

    // Security audit fields
    @CreationTimestamp
    private LocalDateTime createdAt;

    private LocalDateTime revokedAt; // Token iptal edilme zamanı

    private String revokeReason; // İptal nedeni

    @Builder.Default
    private int useCount = 0; // Token kaç kez kullanıldı

    // Suspicious activity detection
    @Builder.Default
    private boolean suspiciousActivity = false;

    private String suspiciousReason;

    // Geographical information
    private String country;
    private String city;
    private String region;

    // Device fingerprinting
    private String deviceFingerprint;

    @PrePersist
    private void prePersist() {
        if (issuedAt == null) {
            issuedAt = LocalDateTime.now();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    @PreUpdate
    private void preUpdate() {
        if (lastUsedAt == null) {
            lastUsedAt = LocalDateTime.now();
        }
        useCount++;
    }

    // Token'ı geçersiz kılma
    public void revoke(String reason) {
        this.isValid = false;
        this.revokedAt = LocalDateTime.now();
        this.revokeReason = reason;
    }

    // Token'ın expire olup olmadığını kontrol etme
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    // Token'ın aktif olup olmadığını kontrol etme
    public boolean isActive() {
        return isValid && !isExpired() && revokedAt == null;
    }

    // Token'ın şüpheli olarak işaretlenmesi
    public void markSuspicious(String reason) {
        this.suspiciousActivity = true;
        this.suspiciousReason = reason;
    }

    // Token'ı son kullanım zamanıyla güncelleme
    public void updateLastUsed() {
        this.lastUsedAt = LocalDateTime.now();
        this.useCount++;
    }
}