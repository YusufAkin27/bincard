package akin.city_card.superadmin.core.request;

import lombok.Data;

import java.util.List;

@Data
public class BulkRoleAssignmentRequest {
    private Long adminId;
    private List<String> roles;
}
