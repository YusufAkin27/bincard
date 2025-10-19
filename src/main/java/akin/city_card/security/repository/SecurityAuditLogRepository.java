package akin.city_card.security.repository;

import akin.city_card.security.entity.SecurityAuditLog;
import akin.city_card.security.entity.SecurityEventType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    List<SecurityAuditLog> findByUsernameOrderByTimestampDesc(String username);

    List<SecurityAuditLog> findByIpAddressOrderByTimestampDesc(String ipAddress);

    List<SecurityAuditLog> findByEventTypeOrderByTimestampDesc(SecurityEventType eventType);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.timestamp >= :since AND s.success = false ORDER BY s.timestamp DESC")
    List<SecurityAuditLog> findFailedEventsSince(@Param("since") LocalDateTime since);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.timestamp >= :since AND s.eventType = 'SUSPICIOUS_ACTIVITY' ORDER BY s.timestamp DESC")
    List<SecurityAuditLog> findSuspiciousActivitiesSince(@Param("since") LocalDateTime since);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.ipAddress = :ipAddress AND s.eventType = 'LOGIN_FAILED' AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityAuditLog> findFailedLoginsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.username = :username AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityAuditLog> findUserActivitySince(@Param("username") String username, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(s) FROM SecurityAuditLog s WHERE s.ipAddress = :ipAddress AND s.eventType = 'LOGIN_FAILED' AND s.timestamp >= :since")
    long countFailedLoginsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.severity = 'HIGH' AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityAuditLog> findHighSeverityEventsSince(@Param("since") LocalDateTime since);

    @Modifying
    @Transactional
    @Query("DELETE FROM SecurityAuditLog s WHERE s.timestamp < :cutoffDate")
    int deleteOldAuditLogs(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT DISTINCT s.ipAddress FROM SecurityAuditLog s WHERE s.eventType IN ('SUSPICIOUS_ACTIVITY', 'BRUTE_FORCE_ATTEMPT') AND s.timestamp >= :since")
    List<String> findSuspiciousIpsSince(@Param("since") LocalDateTime since);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.riskScore >= :minRiskScore AND s.timestamp >= :since ORDER BY s.riskScore DESC, s.timestamp DESC")
    List<SecurityAuditLog> findHighRiskEventsSince(@Param("minRiskScore") Integer minRiskScore, @Param("since") LocalDateTime since);
}