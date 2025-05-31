package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "security_users") // 'user' yerine güvenli bir tablo adı
@Inheritance(strategy = InheritanceType.JOINED)
public class SecurityUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String userNumber; // telefon numarası (username olarak kullanılacak)

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
        return true; // isteğe bağlı değiştirilebilir
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // isteğe bağlı değiştirilebilir
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // isteğe bağlı değiştirilebilir
    }

    @Override
    public boolean isEnabled() {
        return true; // isteğe bağlı değiştirilebilir
    }
}
