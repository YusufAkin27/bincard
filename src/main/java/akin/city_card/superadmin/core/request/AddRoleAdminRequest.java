package akin.city_card.superadmin.core.request;

import akin.city_card.security.entity.Role;
import lombok.Data;

import java.util.List;

@Data
public class AddRoleAdminRequest {
    private Long adminId;
    private List<Role> roles;
}
