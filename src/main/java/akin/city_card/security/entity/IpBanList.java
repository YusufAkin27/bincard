package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "ip_ban_list",
        indexes = {
                @Index(name = "idx_ip_ban_ip_address", columnList = "ipAddress"),
                @Index(name = "idx_ip_ban_expires_at", columnList = "expiresAt"),
                @Index(name = "idx_ip_ban_is_active", columnList = "isActive")
        }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IpBanList {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 45)
    private String ipAddress;

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

    // Geografik bilgiler
    private String country;
    private String city;
    private String region;

    // İstatistik
    @Builder.Default
    private Integer affectedUserCount = 0;

    @Column(length = 1000)
    private String notes;

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
