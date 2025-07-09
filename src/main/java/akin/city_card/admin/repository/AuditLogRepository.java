package akin.city_card.admin.repository;

import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog,Long> {
    List<AuditLog> findByUser_UserNumberAndActionAndTimestampBetween(String username, ActionType actionType, LocalDateTime from, LocalDateTime to);

    List<AuditLog> findByUser_UserNumberAndTimestampBetween(String username, LocalDateTime from, LocalDateTime to);

    Page<AuditLog> findByUser_UserNumberOrderByTimestampDesc(String username, Pageable pageable);

    Page<AuditLog> findByUser(User user, Pageable pageable);

    List<AuditLog> findByActionAndTimestampBetween(ActionType actionType, LocalDateTime from, LocalDateTime to);

    List<AuditLog> findByTimestampBetween(LocalDateTime from, LocalDateTime to);
}
