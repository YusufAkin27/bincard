package akin.city_card.service;

import akin.city_card.verification.repository.VerificationCodeRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class VerificationCodeService {

    private final VerificationCodeRepository verificationCodeRepository;

    public VerificationCodeService(VerificationCodeRepository verificationCodeRepository) {
        this.verificationCodeRepository = verificationCodeRepository;
    }

    // Her gün saat 02:00'de süresi dolan kodları sil
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanExpiredVerificationCodes() {
        verificationCodeRepository.deleteExpiredCodes();
        System.out.println("Süresi dolan doğrulama kodları temizlendi: " + java.time.LocalDateTime.now());
    }
}
