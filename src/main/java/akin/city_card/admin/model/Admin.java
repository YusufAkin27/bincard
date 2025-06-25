package akin.city_card.admin.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@Entity
@SuperBuilder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "admins")
public class Admin extends SecurityUser {

    @Column(name = "super_admin_approved", nullable = false)
    private boolean superAdminApproved;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "registered_at", nullable = false, updatable = false)
    private LocalDateTime registeredAt;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "last_login_device")
    private String lastLoginDevice;

    @Column(name = "last_login_platform")
    private String lastLoginPlatform;

    @Column(name = "last_login_app_version")
    private String lastLoginAppVersion;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(nullable = false)
    private boolean isActive = false;

    @Column(nullable = false)
    private boolean isDeleted = false;

    @PrePersist
    protected void onCreate() {
        this.registeredAt = LocalDateTime.now();
    }
}
