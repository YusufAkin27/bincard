package akin.city_card.scheduler;

import akin.city_card.verification.repository.VerificationCodeRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@Slf4j
public class VerificationCodeScheduler {

    private final VerificationCodeRepository verificationCodeRepository;

    public VerificationCodeScheduler(VerificationCodeRepository verificationCodeRepository) {
        this.verificationCodeRepository = verificationCodeRepository;
    }

    // Her gün saat 02:00'de süresi dolan kodları sil
    @Scheduled(cron = "0 */3 * * * *")
    public void cleanExpiredVerificationCodes() {
        verificationCodeRepository.deleteExpiredCodes();
        System.out.println("Süresi dolan doğrulama kodları temizlendi: " + java.time.LocalDateTime.now());
        log.info("[Scheduler] Süresi dolan doğrulama kodları silindi - Zaman: {}", LocalDateTime.now());

    }
}
