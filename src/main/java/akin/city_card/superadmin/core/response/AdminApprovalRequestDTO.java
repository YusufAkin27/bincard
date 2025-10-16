package akin.city_card.superadmin.core.response;

import akin.city_card.admin.model.ApprovalStatus;
import akin.city_card.superadmin.model.SuperAdmin;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AdminApprovalRequestDTO {
    private Long id;
    private String adminName;
    private String adminTelephone;
    private SuperAdmin approvedBy;
    private LocalDateTime approvedAt;
    private LocalDateTime requestedAt;
    private LocalDateTime updateAt;
    private LocalDateTime createdAt;
    private ApprovalStatus status;
    private String note;
}
