package akin.city_card.admin.repository;

import akin.city_card.admin.model.AdminApprovalRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminApprovalRequestRepository extends JpaRepository<AdminApprovalRequest,Integer> {
}
