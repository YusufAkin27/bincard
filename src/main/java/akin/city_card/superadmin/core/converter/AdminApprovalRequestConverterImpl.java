package akin.city_card.superadmin.core.converter;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.superadmin.core.response.AdminApprovalRequestDTO;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AdminApprovalRequestConverterImpl implements AdminApprovalRequestConverter {

    @Override
    public AdminApprovalRequestDTO toDTO(AdminApprovalRequest adminApprovalRequest) {
        if (adminApprovalRequest == null) {
            return null;
        }

        return AdminApprovalRequestDTO.builder()
                .id(adminApprovalRequest.getId())
                .requestedAt(adminApprovalRequest.getRequestedAt())
                .adminName(
                        Optional.ofNullable(adminApprovalRequest.getAdmin())
                                .map(SecurityUser::getProfileInfo)
                                .map(ProfileInfo::getName)
                                .orElse(null)
                )
                .adminTelephone(
                        Optional.ofNullable(adminApprovalRequest.getAdmin())
                                .map(SecurityUser::getUserNumber)
                                .orElse(null)
                )
                .approvedAt(adminApprovalRequest.getApprovedAt())
                .approvedBy(adminApprovalRequest.getApprovedBy())
                .status(adminApprovalRequest.getStatus())
                .note(adminApprovalRequest.getNote())
                .createdAt(adminApprovalRequest.getCreatedAt())
                .updateAt(adminApprovalRequest.getUpdateAt())
                .build();
    }
}
