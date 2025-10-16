package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "device_ban_list", indexes = {
        @Index(name = "idx_device_id", columnList = "deviceId"),
        @Index(name = "idx_device_fingerprint", columnList = "deviceFingerprint"),
        @Index(name = "idx_is_active", columnList = "isActive"),
        @Index(name = "idx_user_id", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceBanList {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser user;

    @Column(nullable = false)
    private String deviceId;

    private String deviceFingerprint; // Device fingerprinting için

    @Column(nullable = false)
    private String deviceName;

    private String deviceModel;
    private String operatingSystem;
    private String browserName;
    private String appVersion;

    @Column(nullable = false)
    private String reason;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "banned_by_user_id", nullable = false)
    private SecurityUser bannedBy;

    @CreationTimestamp
    @Column(nullable = false)
    private LocalDateTime bannedAt;

    private LocalDateTime expiresAt; // null ise kalıcı engel

    @Builder.Default
    @Column(nullable = false)
    private Boolean isActive = true;

    private LocalDateTime unbannedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "unbanned_by_user_id")
    private SecurityUser unbannedBy;

    private String unbanReason;

    // Son bilinen IP ve lokasyon
    private String lastKnownIp;
    private String lastKnownCity;
    private String lastKnownCountry;

    @Column(length = 1000)
    private String notes;

    // Ban severity
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private BanSeverity severity = BanSeverity.MEDIUM;

    public enum BanSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    // Helper methods
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isCurrentlyActive() {
        return isActive && !isExpired();
    }

    public void unban(SecurityUser unbannedBy, String reason) {
        this.isActive = false;
        this.unbannedAt = LocalDateTime.now();
        this.unbannedBy = unbannedBy;
        this.unbanReason = reason;
    }
}