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

    // Super admin bu kişiyi onayladı mı
    @Column(name = "super_admin_approved", nullable = false)
    private boolean superAdminApproved;

    // Onay tarihi (nullable olabilir)
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    // Admin kayıt tarihi
    @Column(name = "registered_at", nullable = false, updatable = false)
    private LocalDateTime registeredAt;

    // Son başarılı giriş zamanı
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;
    private boolean isActive;
    private boolean isDeleted;



    @PrePersist
    protected void onCreate() {
        this.registeredAt = LocalDateTime.now();
    }


}
