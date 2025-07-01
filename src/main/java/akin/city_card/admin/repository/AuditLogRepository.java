package akin.city_card.admin.repository;

import akin.city_card.admin.model.AuditLog;
import org.springframework.data.domain.Auditable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog,Long> {
}
