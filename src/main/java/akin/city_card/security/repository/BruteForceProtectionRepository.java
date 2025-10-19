package akin.city_card.security.repository;

import akin.city_card.security.entity.BruteForceProtection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BruteForceProtectionRepository extends JpaRepository<BruteForceProtection, Long> {

    Optional<BruteForceProtection> findByIdentifier(String identifier);

    @Query("SELECT bf FROM BruteForceProtection bf WHERE bf.lockedUntil > :now")
    List<BruteForceProtection> findCurrentlyLocked(@Param("now") LocalDateTime now);

    @Query("SELECT bf FROM BruteForceProtection bf WHERE bf.failedAttempts >= :maxAttempts AND bf.lastAttemptTime >= :since")
    List<BruteForceProtection> findSuspiciousAccounts(@Param("maxAttempts") int maxAttempts, @Param("since") LocalDateTime since);

    @Query("SELECT DISTINCT bf.lastIpAddress FROM BruteForceProtection bf WHERE bf.failedAttempts >= :threshold AND bf.lastAttemptTime >= :since AND bf.lastIpAddress IS NOT NULL")
    List<String> findSuspiciousIPs(@Param("since") LocalDateTime since, @Param("threshold") int threshold);

    @Modifying
    @Transactional
    @Query("DELETE FROM BruteForceProtection bf WHERE bf.lastAttemptTime < :cutoffDate AND bf.lockedUntil IS NULL")
    int deleteOldRecords(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT COUNT(bf) FROM BruteForceProtection bf WHERE bf.lastIpAddress = :ipAddress AND bf.lastAttemptTime >= :since")
    long countAttemptsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);
}