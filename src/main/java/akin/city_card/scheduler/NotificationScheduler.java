package akin.city_card.scheduler;

import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;

@Slf4j
@Component
@RequiredArgsConstructor
public class NotificationScheduler {

    private final UserRepository userRepository;
    private final FCMService fcmService;

    private static final List<String> TITLES = List.of(
            "Günün Bilgisi", "Hatırlatma", "Küçük Bir İpucu", "Bilgilendirme"
    );

    private static final List<String> MESSAGES = List.of(
            "Bugün toplu taşıma ile doğayı koruyun 🌱",
            "Kart bakiyenizi kontrol etmeyi unutmayın!",
            "CityCard ile yeni kampanyaları kaçırmayın!",
            "Favori rotalarınızı belirlemeyi denediniz mi?",
            "Uygulamanız güncel mi? Yeni özellikler eklenmiş olabilir!"
    );

    private static final Random RANDOM = new Random();

    @Scheduled(cron = "0 0 9 * * *")
    public void sendMorningNotifications() {
        sendBulkNotifications("Sabah");
    }

    @Scheduled(cron = "0 0 18 * * *")
    public void sendEveningNotifications() {
        sendBulkNotifications("Akşam");
    }

    private void sendBulkNotifications(String period) {
        List<User> users = userRepository.findAll();

        for (User user : users) {
            String title = TITLES.get(RANDOM.nextInt(TITLES.size()));
            String message = MESSAGES.get(RANDOM.nextInt(MESSAGES.size()));

            try {
                fcmService.sendNotificationToToken(
                        user,
                        title + " " + period,
                        message,
                        NotificationType.INFO,
                        null
                );
            } catch (Exception e) {
                log.error("Bildirim gönderilemedi. Kullanıcı: {}, Hata: {}", user.getId(), e.getMessage());
            }
        }
    }
}
