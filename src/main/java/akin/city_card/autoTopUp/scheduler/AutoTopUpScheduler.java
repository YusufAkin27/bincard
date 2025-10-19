package akin.city_card.autoTopUp.scheduler;

import akin.city_card.autoTopUp.service.abstracts.AutoTopUpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AutoTopUpScheduler {

    private final AutoTopUpService autoTopUpService;

    /**
     * Her 5 dakikada bir tüm aktif otomatik yükleme konfigürasyonlarını kontrol eder
     * Eşik değerin altına düşen kartları otomatik olarak yükler
     */
    @Scheduled(fixedRate = 300000) // 5 dakika = 300,000 ms
    public void processScheduledAutoTopUps() {
        log.debug("Otomatik yükleme scheduler başlatıldı");

        try {
            autoTopUpService.processAllPendingAutoTopUps();
            log.debug("Otomatik yükleme scheduler tamamlandı");
        } catch (Exception e) {
            log.error("Otomatik yükleme scheduler sırasında hata oluştu: ", e);
        }
    }

    /**
     * Her gün saat 02:00'da otomatik yükleme sistem temizliği yapar
     * (Gelecekte eklenebilecek temizlik işlemleri için)
     */
    @Scheduled(cron = "0 0 2 * * ?") // Her gün saat 02:00
    public void dailyMaintenance() {
        log.info("Otomatik yükleme sistemi günlük bakım işlemi başlatıldı");

        try {
            // Burada gelecekte eski logları temizleme, 
            // performans optimizasyonu vb. işlemler yapılabilir

            log.info("Otomatik yükleme sistemi günlük bakım işlemi tamamlandı");
        } catch (Exception e) {
            log.error("Otomatik yükleme günlük bakım sırasında hata oluştu: ", e);
        }
    }
}
