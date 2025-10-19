package akin.city_card.security.service;

import akin.city_card.security.entity.BruteForceProtection;
import akin.city_card.security.filter.SecurityAuditService;
import akin.city_card.security.repository.BruteForceProtectionRepository;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class BruteForceProtectionService {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceProtectionService.class);

    private final BruteForceProtectionRepository bruteForceRepository;
    private final UserRepository userRepository;
    private final SecurityAuditService auditService;

    @Value("${security.brute-force.max-attempts:5}")
    private int maxAttempts;

    @Value("${security.brute-force.lockout-minutes:15}")
    private int lockoutMinutes;

    @Value("${security.brute-force.reset-attempts-minutes:60}")
    private int resetAttemptsMinutes;

    /**
     * Login başarısız olduğunda çağrılır
     */
    @Transactional
    public void recordFailedLogin(String identifier, String ipAddress, String userAgent) {
        BruteForceProtection protection = bruteForceRepository
                .findByIdentifier(identifier)
                .orElse(createNewProtection(identifier));

        protection.setLastAttemptTime(LocalDateTime.now());
        protection.setLastIpAddress(ipAddress);
        protection.setLastUserAgent(userAgent);

        // Eğer son başarısız deneme resetAttemptsMinutes'dan daha eskiyse, sayacı sıfırla
        if (protection.getFailedAttempts() > 0 &&
                protection.getLastAttemptTime().isBefore(LocalDateTime.now().minusMinutes(resetAttemptsMinutes))) {
            protection.setFailedAttempts(1);
            logger.info("Resetting failed attempts for identifier: {} due to time window", identifier);
        } else {
            protection.setFailedAttempts(protection.getFailedAttempts() + 1);
        }

        // Maksimum deneme sayısına ulaşıldıysa hesabı kilitle
        if (protection.getFailedAttempts() >= maxAttempts) {
            lockAccount(protection);
        }

        bruteForceRepository.save(protection);

        logger.warn("Failed login attempt #{} for identifier: {} from IP: {}",
                protection.getFailedAttempts(), identifier, ipAddress);
    }

    /**
     * Login başarılı olduğunda çağrılır
     */
    @Transactional
    public void recordSuccessfulLogin(String identifier) {
        Optional<BruteForceProtection> protectionOpt = bruteForceRepository.findByIdentifier(identifier);

        if (protectionOpt.isPresent()) {
            BruteForceProtection protection = protectionOpt.get();
            protection.setFailedAttempts(0);
            protection.setLockedUntil(null);
            protection.setLastSuccessfulLogin(LocalDateTime.now());
            bruteForceRepository.save(protection);

            logger.info("Successful login recorded for identifier: {}, attempts reset", identifier);
        }
    }

    /**
     * Hesabın kilitli olup olmadığını kontrol eder
     */
    public boolean isAccountLocked(String identifier) {
        Optional<BruteForceProtection> protectionOpt = bruteForceRepository.findByIdentifier(identifier);

        if (protectionOpt.isEmpty()) {
            return false;
        }

        BruteForceProtection protection = protectionOpt.get();

        // Kilit süresi geçmişse kilidi kaldır
        if (protection.getLockedUntil() != null &&
                protection.getLockedUntil().isBefore(LocalDateTime.now())) {
            unlockAccount(protection);
            return false;
        }

        return protection.getLockedUntil() != null &&
                protection.getLockedUntil().isAfter(LocalDateTime.now());
    }

    /**
     * Kalan kilit süresini dakika cinsinden döndürür
     */
    public long getRemainingLockTimeMinutes(String identifier) {
        Optional<BruteForceProtection> protectionOpt = bruteForceRepository.findByIdentifier(identifier);

        if (protectionOpt.isEmpty()) {
            return 0;
        }

        BruteForceProtection protection = protectionOpt.get();

        if (protection.getLockedUntil() == null ||
                protection.getLockedUntil().isBefore(LocalDateTime.now())) {
            return 0;
        }

        return java.time.Duration.between(LocalDateTime.now(), protection.getLockedUntil()).toMinutes();
    }

    /**
     * Kalan deneme hakkını döndürür
     */
    public int getRemainingAttempts(String identifier) {
        Optional<BruteForceProtection> protectionOpt = bruteForceRepository.findByIdentifier(identifier);

        if (protectionOpt.isEmpty()) {
            return maxAttempts;
        }

        BruteForceProtection protection = protectionOpt.get();

        // Eğer reset süresi geçmişse tüm hakkı ver
        if (protection.getLastAttemptTime() != null &&
                protection.getLastAttemptTime().isBefore(LocalDateTime.now().minusMinutes(resetAttemptsMinutes))) {
            return maxAttempts;
        }

        return Math.max(0, maxAttempts - protection.getFailedAttempts());
    }

    /**
     * Hesabı manuel olarak kilitle
     */
    @Transactional
    public void manuallyLockAccount(String identifier, String reason, String adminUsername) {
        BruteForceProtection protection = bruteForceRepository
                .findByIdentifier(identifier)
                .orElse(createNewProtection(identifier));

        protection.setLockedUntil(LocalDateTime.now().plusHours(24)); // 24 saat kilitle
        protection.setLockReason("Manual lock by admin: " + reason);
        protection.setFailedAttempts(maxAttempts);

        bruteForceRepository.save(protection);

        // Kullanıcının durumunu da güncelle
        userRepository.findByUserNumber(identifier).ifPresent(user -> {
            user.setStatus(UserStatus.FROZEN);
            userRepository.save(user);
        });

        logger.warn("Account manually locked by admin: {} for identifier: {} - Reason: {}",
                adminUsername, identifier, reason);
    }

    /**
     * Hesabı manuel olarak kilidini aç
     */
    @Transactional
    public void manuallyUnlockAccount(String identifier, String adminUsername) {
        Optional<BruteForceProtection> protectionOpt = bruteForceRepository.findByIdentifier(identifier);

        if (protectionOpt.isPresent()) {
            BruteForceProtection protection = protectionOpt.get();
            protection.setLockedUntil(null);
            protection.setFailedAttempts(0);
            protection.setLockReason("Unlocked by admin: " + adminUsername);

            bruteForceRepository.save(protection);

            // Kullanıcının durumunu da güncelle
            userRepository.findByUserNumber(identifier).ifPresent(user -> {
                user.setStatus(UserStatus.ACTIVE);
                userRepository.save(user);
            });

            logger.info("Account manually unlocked by admin: {} for identifier: {}",
                    adminUsername, identifier);
        }
    }

    private BruteForceProtection createNewProtection(String identifier) {
        return BruteForceProtection.builder()
                .identifier(identifier)
                .failedAttempts(0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Transactional
    public void lockAccount(BruteForceProtection protection) {
        LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(lockoutMinutes);
        protection.setLockedUntil(lockUntil);
        protection.setLockReason("Automatic lock due to multiple failed login attempts");

        // Kullanıcıyı da dondur
        userRepository.findByUserNumber(protection.getIdentifier()).ifPresent(user -> {
            user.setStatus(UserStatus.FROZEN);
            userRepository.save(user);

            logger.error("User account frozen due to brute force: {} until {}",
                    protection.getIdentifier(), lockUntil);
        });
    }

    @Transactional
    public void unlockAccount(BruteForceProtection protection) {
        protection.setLockedUntil(null);
        protection.setFailedAttempts(0);

        // Kullanıcıyı aktif yap
        userRepository.findByUserNumber(protection.getIdentifier()).ifPresent(user -> {
            if (user.getStatus() == UserStatus.FROZEN) {
                user.setStatus(UserStatus.ACTIVE);
                userRepository.save(user);

                logger.info("User account automatically unlocked: {}", protection.getIdentifier());
            }
        });

        bruteForceRepository.save(protection);
    }

    /**
     * Eski kayıtları temizle (scheduled task)
     */
    @Scheduled(cron = "0 0 2 * * ?") // Her gün saat 02:00'da çalış
    @Transactional
    public void cleanupOldRecords() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(30);
        int deletedCount = bruteForceRepository.deleteOldRecords(cutoffDate);

        if (deletedCount > 0) {
            logger.info("Cleaned up {} old brute force protection records", deletedCount);
        }
    }

    /**
     * Şüpheli IP'leri bul
     */
    public java.util.List<String> getSuspiciousIPs(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return bruteForceRepository.findSuspiciousIPs(since, maxAttempts);
    }
}