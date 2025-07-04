package akin.city_card.admin.repository;

import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog,Long> {
    List<AuditLog> findByTelephoneAndActionAndTimestampBetween(String username, ActionType actionType, LocalDateTime from, LocalDateTime to);

    List<AuditLog> findByTelephoneAndTimestampBetween(String username, LocalDateTime from, LocalDateTime to);
}
