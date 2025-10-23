package akin.city_card.admin.model;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // İşlemi yapan kullanıcı (Admin veya User olabilir)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private SecurityUser user;

    // İşlemi yapan admin (Admin işlemleri için)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_id")
    private Admin admin;

    @Enumerated(EnumType.STRING)
    private ActionType action;

    @Column(length = 1000)
    private String description;

    private LocalDateTime timestamp;

    // IP ve cihaz bilgisi
    @Embedded
    private DeviceInfo deviceInfo;

    private Long targetEntityId;

    private String targetEntityType;

    private Double amount;

    @Column(length = 2000)
    private String metadata;

    @Column(length = 1000)
    private String referer;
}
