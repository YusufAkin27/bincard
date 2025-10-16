package akin.city_card.security.entity;

import akin.city_card.admin.model.AuditLog;
import akin.city_card.contract.model.UserContractAcceptance;
import akin.city_card.location.model.Location;
import akin.city_card.user.model.DeviceHistory;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.UserStatus;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String userNumber;

    @Column(nullable = false)
    @JsonIgnore
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;

    @Embedded
    private DeviceInfo currentDeviceInfo;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("lastSeenAt DESC")
    @JsonIgnore
    private List<DeviceHistory> deviceHistory = new ArrayList<>();


    @Embedded
    private ProfileInfo profileInfo;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.UNVERIFIED;

    private boolean isDeleted = false;
    private boolean emailVerified = false;
    private boolean phoneVerified = false;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("loginAt DESC")
    @JsonIgnore
    private List<LoginHistory> loginHistory = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("recordedAt DESC")
    @JsonIgnore
    private List<Location> locationHistory = new ArrayList<>();


    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JsonIgnore
    private List<AuditLog> auditLogs = new ArrayList<>();

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "last_location_id")
    @JsonIgnore
    private Location lastKnownLocation;

    @JsonIgnore
    private LocalDateTime lastLocationUpdatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("acceptedAt DESC")
    @JsonIgnore
    private List<UserContractAcceptance> contractAcceptances = new ArrayList<>();


    public SecurityUser(String userNumber, Set<Role> roles) {
        this.userNumber = userNumber;
        this.roles = roles;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toSet());
    }

    public boolean hasRole(String roleName) {
        if (roles == null) return false;
        return roles.stream()
                .map(Role::getAuthority)
                .anyMatch(r -> r.equalsIgnoreCase(roleName));
    }


    @Override
    public String getUsername() {
        return userNumber;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return isAccountNonExpired();
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return isAccountNonLocked();
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return !isDeleted && status == UserStatus.ACTIVE;
    }
}
