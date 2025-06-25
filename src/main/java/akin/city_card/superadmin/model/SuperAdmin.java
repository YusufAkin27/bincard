package akin.city_card.superadmin.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class SuperAdmin extends SecurityUser {

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
    private boolean isActive = true;

    @Column(nullable = false)
    private boolean isDeleted = false;
}
