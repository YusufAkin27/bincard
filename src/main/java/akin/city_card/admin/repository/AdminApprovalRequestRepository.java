package akin.city_card.admin.repository;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.admin.model.ApprovalStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminApprovalRequestRepository extends JpaRepository<AdminApprovalRequest, Integer> {
    Page<AdminApprovalRequest> findByStatus(ApprovalStatus approvalStatus, Pageable pageable);
}
