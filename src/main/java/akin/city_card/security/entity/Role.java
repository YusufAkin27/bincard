package akin.city_card.security.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    ADMIN("ADMIN"),
    SUPERADMIN("SUPERADMIN"),
    USER("USER"),
    DRIVER("DRIVER"),
    MODERATOR("MODERATOR");



    private final String role;
    @Override
    public String getAuthority() {
        return role;
    }
}
