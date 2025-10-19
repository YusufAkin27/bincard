package akin.city_card.superadmin.core.request;

import akin.city_card.security.entity.Role;
import akin.city_card.validations.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UpdateAdminRequest {
    private String name;
    private String surname;

    @ValidPassword
    private String password;
    @ValidEmail
    @UniqueEmail
    private String email;


    private List<Role> roles;
}
