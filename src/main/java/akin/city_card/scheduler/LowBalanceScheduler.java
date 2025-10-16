/*package akin.city_card.scheduler;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class LowBalanceScheduler {

    private final UserRepository userRepository;
    private final FCMService fcmService;

    @Scheduled(fixedRate = 60_000)
    public void checkLowBalancesAndNotify() {
        Iterable<User> users = userRepository.findAll();

        for (User user : users) {
            Map<BusCard, Double> alerts = user.getLowBalanceAlerts();
            if (alerts == null || alerts.isEmpty()) continue;

            for (Map.Entry<BusCard, Double> entry : alerts.entrySet()) {
                BusCard card = entry.getKey();
                Double thresholdDouble = entry.getValue();
                if (thresholdDouble == null) continue;

                BigDecimal threshold = BigDecimal.valueOf(thresholdDouble);
                BigDecimal balance = card.getBalance();
                if (balance == null) continue;

                if (balance.compareTo(threshold) < 0 && !card.isLowBalanceNotified()) {
                    String title = "Düşük Bakiye Uyarısı";
                    String message = String.format("Kart bakiyeniz %.2f TL'nin altında: %.2f TL",
                            threshold.doubleValue(), balance.doubleValue());
                    fcmService.sendNotificationToToken(user, title, message, NotificationType.WARNING, null);

                    card.setLowBalanceNotified(true);
                } else if (balance.compareTo(threshold) >= 0 && card.isLowBalanceNotified()) {
                    card.setLowBalanceNotified(false);
                }
            }
        }
    }
}


 */