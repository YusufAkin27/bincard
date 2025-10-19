package akin.city_card.superadmin.core.converter;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.superadmin.core.response.AdminApprovalRequestDTO;

public interface AdminApprovalRequestConverter {

    AdminApprovalRequestDTO toDTO(AdminApprovalRequest adminApprovalRequest);
}
