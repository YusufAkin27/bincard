package akin.city_card.scheduler;

import akin.city_card.news.model.News;
import akin.city_card.news.repository.NewsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class NewsSchedulerService {

    private final NewsRepository newsRepository;

    @Scheduled(fixedRate = 300000) // 5 dakika = 300,000 ms
    @Transactional
    public void activateScheduledNews() {
        LocalDateTime now = LocalDateTime.now();
        
        List<News> newsToActivate = newsRepository.findByStartDateBeforeAndActiveFalse(now);
        
        if (!newsToActivate.isEmpty()) {
            log.info("Activating {} scheduled news items", newsToActivate.size());
            
            for (News news : newsToActivate) {
                news.setActive(true);
                log.info("Activated news: {} (ID: {})", news.getTitle(), news.getId());
            }
            
            newsRepository.saveAll(newsToActivate);
        }
    }

    /**
     * Her 10 dakikada bir çalışır ve bitiş tarihi geçmiş haberleri pasif yapar
     */
    @Scheduled(fixedRate = 600000) // 10 dakika = 600,000 ms
    @Transactional
    public void deactivateExpiredNews() {
        LocalDateTime now = LocalDateTime.now();
        
        // Bitiş tarihi geçmiş ama hala aktif olan haberleri bul
        List<News> newsToDeactivate = newsRepository.findByEndDateBeforeAndActiveTrue(now);
        
        if (!newsToDeactivate.isEmpty()) {
            log.info("Deactivating {} expired news items", newsToDeactivate.size());
            
            for (News news : newsToDeactivate) {
                news.setActive(false);
                log.info("Deactivated expired news: {} (ID: {})", news.getTitle(), news.getId());
            }
            
            newsRepository.saveAll(newsToDeactivate);
        }
    }


    @Scheduled(cron = "0 0 1 * * *") // Her gün saat 01:00
    @Transactional
    public void dailyNewsStatusCheck() {
        LocalDateTime now = LocalDateTime.now();
        
        log.info("Starting daily news status check at {}", now);
        
        // Tüm haberlerin durumlarını kontrol et
        List<News> allNews = newsRepository.findAll();
        int activatedCount = 0;
        int deactivatedCount = 0;
        
        for (News news : allNews) {
            boolean shouldBeActive = shouldNewsBeActive(news, now);
            
            if (shouldBeActive && !news.isActive()) {
                news.setActive(true);
                activatedCount++;
                log.info("Daily check - Activated news: {} (ID: {})", news.getTitle(), news.getId());
            } else if (!shouldBeActive && news.isActive()) {
                news.setActive(false);
                deactivatedCount++;
                log.info("Daily check - Deactivated news: {} (ID: {})", news.getTitle(), news.getId());
            }
        }
        
        if (activatedCount > 0 || deactivatedCount > 0) {
            newsRepository.saveAll(allNews);
            log.info("Daily check completed - Activated: {}, Deactivated: {}", activatedCount, deactivatedCount);
        } else {
            log.info("Daily check completed - No status changes needed");
        }
    }

    /**
     * Haberin aktif olup olmaması gerektiğini kontrol eder
     */
    private boolean shouldNewsBeActive(News news, LocalDateTime now) {
        // Başlangıç tarihi henüz gelmemişse pasif olmalı
        if (news.getStartDate() != null && news.getStartDate().isAfter(now)) {
            return false;
        }
        
        // Bitiş tarihi geçmişse pasif olmalı
        if (news.getEndDate() != null && news.getEndDate().isBefore(now)) {
            return false;
        }
        
        // Diğer durumlarda aktif olmalı
        return true;
    }

    /**
     * Manuel olarak tüm haberlerin durumlarını kontrol etmek için
     */
    @Transactional
    public void manualNewsStatusCheck() {
        log.info("Manual news status check triggered");
        dailyNewsStatusCheck();
    }
}