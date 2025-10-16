package akin.city_card.admin.repository;

import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    // 1. Belirli kullanıcı ve actionType ile zaman aralığına göre filtreleme
    List<AuditLog> findByUser_UserNumberAndActionAndTimestampBetween(
            String username, ActionType actionType, LocalDateTime from, LocalDateTime to);

    // 2. Belirli kullanıcı ve zaman aralığına göre filtreleme
    List<AuditLog> findByUser_UserNumberAndTimestampBetween(
            String username, LocalDateTime from, LocalDateTime to);

    // 3. Belirli kullanıcıya ait loglar (pagination destekli)
    Page<AuditLog> findByUser(User user, Pageable pageable);

    // 4. Belirli actionType ve zaman aralığına göre filtreleme
    List<AuditLog> findByActionAndTimestampBetween(
            ActionType actionType, LocalDateTime from, LocalDateTime to);

    // 5. Sadece zaman aralığına göre filtreleme
    List<AuditLog> findByTimestampBetween(
            LocalDateTime from, LocalDateTime to);

    // ❌ HATALI: Spring Data JPA böyle bir isimden metod üretemez
    // Page<AuditLog> findSuspiciousActivities(LocalDateTime start, LocalDateTime end, List<ActionType> suspiciousActions, Pageable pageable);
    // ✅ ÇÖZÜM:
    @Query("""
                SELECT a FROM AuditLog a
                WHERE a.timestamp BETWEEN :start AND :end
                  AND a.action IN :suspiciousActions
            """)
    Page<AuditLog> findSuspiciousActivities(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end,
            @Param("suspiciousActions") List<ActionType> suspiciousActions,
            Pageable pageable);

    // ❌ HATALI: findAuditLogsByFilters gibi bir isim JPA'de çalışmaz
    // ✅ ÇÖZÜM:
    @Query("""
                SELECT a FROM AuditLog a
                WHERE (:user IS NULL OR a.user = :user)
                  AND (:actionType IS NULL OR a.action = :actionType)
                  AND (:start IS NULL OR a.timestamp >= :start)
                  AND (:end IS NULL OR a.timestamp <= :end)
            """)
    Page<AuditLog> findAuditLogsByFilters(
            @Param("user") User user,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end,
            @Param("actionType") ActionType actionType,
            Pageable pageable);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.user.id = :userId AND a.action = 'LOGIN' AND a.timestamp >= :since")
    int countLogins(@Param("userId") Long userId, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.user.id = :userId AND a.action IN :actions AND a.timestamp >= :since")
    int countActions(@Param("userId") Long userId, @Param("actions") List<ActionType> actions, @Param("since") LocalDateTime since);

    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.timestamp >= :since ORDER BY a.timestamp ASC")
    List<AuditLog> findByUserSince(@Param("userId") Long userId, @Param("since") LocalDateTime since);
}
