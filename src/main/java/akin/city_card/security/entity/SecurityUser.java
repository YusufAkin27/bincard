package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@Table(name = "security_users")
@Inheritance(strategy = InheritanceType.JOINED)
public class SecurityUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String userNumber;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;

    private String fcmToken;

    @Column(name = "device_uuid")
    private String deviceUuid;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "last_known_lat")
    private Double lastKnownLatitude;

    @Column(name = "last_known_lng")
    private Double lastKnownLongitude;

    @Column(name = "last_location_updated_at")
    private LocalDateTime lastLocationUpdatedAt;

    // 🔽 ORTAK ALANLAR (hepsi buraya taşındı)

    @Column(length = 50)
    private String name;

    @Column( length = 50)
    private String surname;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "last_login_device")
    private String lastLoginDevice;

    @Column(name = "last_login_platform")
    private String lastLoginPlatform;

    @Column(name = "last_login_app_version")
    private String lastLoginAppVersion;

    @Column(nullable = false)
    private boolean isActive = true;

    @Column(nullable = false)
    private boolean isDeleted = false;

    @Column(name = "email")
    private String email;

    @Column(name = "email_verified")
    private boolean emailVerified = false;

    @Column(name = "phone_verified")
    private boolean phoneVerified = false;

    @Column(name = "profile_picture")
    private String profilePicture = "https://w7.pngwing.com/pngs/177/551/png-transparent-user-interface-design-computer-icons-default-stephen-salazar-graphy-user-interface-design-computer-wallpaper-sphere-thumbnail.png";

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;


    // ✅ Constructor (roller ile birlikte)
    public SecurityUser(String userNumber, Set<Role> roles) {
        this.userNumber = userNumber;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getUsername() {
        return userNumber;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
