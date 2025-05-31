package akin.city_card.security.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    ADMIN("ADMIN"),
    USER("USER"),
    DRVIER("DRVIER"),
    MODERATOR("MODERATOR");



    private final String role;
    @Override
    public String getAuthority() {
        return role;
    }
}
