package akin.city_card.service;

import akin.city_card.news.model.News;
import akin.city_card.news.repository.NewsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class NewsExpirationScheduler {

    private final NewsRepository newsRepository;

    /**
     * Her saat başı çalışır: süresi dolmuş haberleri pasif hale getirir.
     */
    @Scheduled(fixedRate = 60 * 60 * 1000) // 1 saat
    public void disableExpiredNews() {
        LocalDateTime now = LocalDateTime.now();

        List<News> expired = newsRepository.findAll().stream()
                .filter(news -> news.isActive()
                        && news.getEndDate() != null
                        && news.getEndDate().isBefore(now))
                .toList();

        if (!expired.isEmpty()) {
            expired.forEach(n -> n.setActive(false));
            newsRepository.saveAll(expired);
            log.info("{} haber pasif hale getirildi.", expired.size());
        } else {
            log.info("Süresi dolmuş haber bulunamadı.");
        }
    }
}
