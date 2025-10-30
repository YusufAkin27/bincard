package akin.city_card.admin.core.response;

import akin.city_card.security.entity.Role;
import akin.city_card.user.model.UserStatus;
import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class AdminDTO {
    private String name;
    private String surname;
    private String email;
    private String phoneNumber;
    private boolean emailVerified;
    private boolean phoneNumberVerified;
    private UserStatus status;
    private Set<Role> roles;
}
