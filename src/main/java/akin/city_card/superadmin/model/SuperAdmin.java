package akin.city_card.superadmin.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.Entity;


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

    @Column
    private String lastLoginIp;

    @Column
    private String deviceUuid;

    @Column
    private String appVersion;

    @Column
    private String platform;
    private boolean isDeleted;
    private boolean isActive;

    @Column
    private LocalDateTime lastLoginAt;
}
