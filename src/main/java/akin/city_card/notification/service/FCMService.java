package akin.city_card.notification.service;

import akin.city_card.notification.model.NotificationType;
import akin.city_card.user.model.User;
import com.google.firebase.messaging.*;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class FCMService {

    private final NotificationService notificationService;

    @Async
    public void sendNotificationToToken(User user, String title, String body, NotificationType type, String targetUrl) {
        Locale.setDefault(Locale.ENGLISH);

        notificationService.saveNotification(user, title, body, type, targetUrl);

        if (user.getCurrentDeviceInfo() == null ||
                user.getCurrentDeviceInfo().getFcmToken() == null ||
                user.getCurrentDeviceInfo().getFcmToken().isBlank()) {
            System.out.println("FCM token yok, bildirim gönderilmeyecek.");
            return;
        }

        Notification firebaseNotification = Notification.builder()
                .setTitle(title)
                .setBody(body)
                .build();

        AndroidConfig androidConfig = AndroidConfig.builder()
                .setPriority(AndroidConfig.Priority.HIGH)
                .setNotification(AndroidNotification.builder()
                        .setSound("default")
                        .build())
                .build();

        ApnsConfig apnsConfig = ApnsConfig.builder()
                .setAps(Aps.builder()
                        .setContentAvailable(true)
                        .setSound("default")
                        .build())
                .putHeader("apns-priority", "10")
                .build();

        Message message = Message.builder()
                .setToken(user.getCurrentDeviceInfo().getFcmToken())
                .setNotification(firebaseNotification)
                .setAndroidConfig(androidConfig)
                .setApnsConfig(apnsConfig)
                .build();

        try {
            String response = FirebaseMessaging.getInstance().send(message);
            System.out.println("Bildirim gönderildi: " + response);
        } catch (FirebaseMessagingException e) {
            System.err.println("Bildirim gönderilemedi: " + e.getMessage());
        }
    }

}
