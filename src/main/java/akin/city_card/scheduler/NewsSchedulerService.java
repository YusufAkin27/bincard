package akin.city_card.scheduler;

import akin.city_card.mail.MailService;
import akin.city_card.news.model.News;
import akin.city_card.news.repository.NewsLikeRepository;
import akin.city_card.news.repository.NewsRepository;
import akin.city_card.user.model.User;
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
    private final NewsLikeRepository newsLikeRepository;
    private final MailService mailService;

    @Scheduled(cron = "0 */3 * * * *") // her 3 dakikada bir
    @Transactional
    public void activateScheduledNews() {
        LocalDateTime now = LocalDateTime.now();

        List<News> newsToActivate = newsRepository.findByStartDateBeforeAndActiveFalse(now);

        if (!newsToActivate.isEmpty()) {
            log.info("✅ {} haber yayına alınıyor...", newsToActivate.size());

            for (News news : newsToActivate) {
                news.setActive(true);
                log.info("📢 Aktif edilen haber: {} (ID: {})", news.getTitle(), news.getId());

                // Kullanıcılara e-posta gönder
                List<User> usersToNotify = newsLikeRepository.findDistinctUsersByNewsType(news.getType());
                log.info("📨 {} kullanıcıya e-posta gönderilecek", usersToNotify.size());

                usersToNotify.forEach(user -> {
                    String email = (user.getProfileInfo() != null) ? user.getProfileInfo().getEmail() : null;
                    log.info("📩 E-posta kuyruğa alındı: {} - {}", user.getUserNumber(), email);
                    mailService.sendNewsNotificationEmail(user, news);
                });
            }

            newsRepository.saveAll(newsToActivate);
        } else {
            log.info("🔍 Yayınlanacak planlanmış haber bulunamadı.");
        }
    }

    @Scheduled(cron = "0 */3 * * * *") // her 3 dakikada bir
    @Transactional
    public void deactivateExpiredNews() {
        LocalDateTime now = LocalDateTime.now();
        List<News> newsToDeactivate = newsRepository.findByEndDateBeforeAndActiveTrue(now);

        if (!newsToDeactivate.isEmpty()) {
            log.info("🛑 {} haber süresi geçtiği için pasif yapılıyor...", newsToDeactivate.size());

            for (News news : newsToDeactivate) {
                news.setActive(false);
                log.info("⛔ Pasif hale getirilen haber: {} (ID: {})", news.getTitle(), news.getId());
            }

            newsRepository.saveAll(newsToDeactivate);
        } else {
            log.info("🔍 Süresi geçmiş aktif haber bulunamadı.");
        }
    }

    @Scheduled(cron = "0 */3 * * * *")
    @Transactional
    public void dailyNewsStatusCheck() {
        LocalDateTime now = LocalDateTime.now();
        log.info("🔁 Günlük haber durumu kontrolü başlatıldı: {}", now);

        List<News> allNews = newsRepository.findAll();
        int activatedCount = 0;
        int deactivatedCount = 0;

        for (News news : allNews) {
            boolean shouldBeActive = shouldNewsBeActive(news, now);

            if (shouldBeActive && !news.isActive()) {
                news.setActive(true);
                activatedCount++;
                log.info("✅ Günlük kontrol - Aktif edilen haber: {} (ID: {})", news.getTitle(), news.getId());

                // Kullanıcılara e-posta gönder
                List<User> usersToNotify = newsLikeRepository.findDistinctUsersByNewsType(news.getType());
                log.info("📨 {} kullanıcıya e-posta gönderilecek", usersToNotify.size());

                usersToNotify.forEach(user -> {
                    String email = (user.getProfileInfo() != null) ? user.getProfileInfo().getEmail() : null;
                    log.info("📩 E-posta kuyruğa alındı: {} - {}", user.getUserNumber(), email);
                    mailService.sendNewsNotificationEmail(user, news);
                });
            } else if (!shouldBeActive && news.isActive()) {
                news.setActive(false);
                deactivatedCount++;
                log.info("⛔ Günlük kontrol - Pasif hale getirilen haber: {} (ID: {})", news.getTitle(), news.getId());
            }
        }

        if (activatedCount > 0 || deactivatedCount > 0) {
            newsRepository.saveAll(allNews);
            log.info("🔁 Günlük kontrol tamamlandı - Aktif: {}, Pasif: {}", activatedCount, deactivatedCount);
        } else {
            log.info("🔍 Günlük kontrol tamamlandı - Değişiklik yok");
        }
    }

    private boolean shouldNewsBeActive(News news, LocalDateTime now) {
        if (news.getStartDate() != null && news.getStartDate().isAfter(now)) return false;
        if (news.getEndDate() != null && news.getEndDate().isBefore(now)) return false;
        return true;
    }

    @Transactional
    public void manualNewsStatusCheck() {
        log.info("🧪 Manuel haber kontrolü başlatıldı");
        dailyNewsStatusCheck();
    }
}
