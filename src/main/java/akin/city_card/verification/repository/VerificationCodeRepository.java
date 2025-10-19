package akin.city_card.verification.repository;

import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {
    VerificationCode findTopByCodeAndCancelledFalseAndUsedFalseOrderByCreatedAtDesc(String code);

    @Modifying
    @Transactional
    @Query("UPDATE VerificationCode v SET v.cancelled = true WHERE v.user.id = :userId AND v.purpose = :purpose AND v.used = false AND v.cancelled = false")
    void cancelAllActiveCodes(@Param("userId") Long userId, @Param("purpose") VerificationPurpose purpose);

    @Modifying
    @Transactional
    @Query("DELETE FROM VerificationCode v WHERE v.expiresAt < CURRENT_TIMESTAMP")
    void deleteExpiredCodes();

    Optional<VerificationCode> findFirstByCodeAndUsedFalseAndCancelledFalseOrderByCreatedAtDesc(String code);

    VerificationCode findTopByCodeAndCancelledFalseOrderByCreatedAtDesc(String code);

    List<VerificationCode> findAllByIpAddressAndUserAgentAndUsedFalseAndCancelledFalse(String ipAddress, String deviceInfo);

    VerificationCode findTopByCodeOrderByCreatedAtDesc(String code);

    Optional<VerificationCode> findFirstByCodeOrderByCreatedAtDesc(String token);
}
