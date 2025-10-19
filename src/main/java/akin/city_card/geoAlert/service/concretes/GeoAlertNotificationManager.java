package akin.city_card.geoAlert.service.concretes;

import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.notification.model.Notification;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.repository.NotificationRepository;
import akin.city_card.notification.service.FCMService;
import akin.city_card.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class GeoAlertNotificationManager {

    private final NotificationRepository notificationRepository;
    private final FCMService fcmService;
    // SMS ve Email servisleri buraya eklenebilir

    @Transactional
    public void sendGeoAlertNotification(User user, GeoAlert alert, String message) {
        try {
            // Veritabanı bildirimi oluştur
            Notification notification = Notification.builder()
                    .user(user)
                    .title("Araç Yaklaşıyor!")
                    .message(message)
                    .type(NotificationType.GEO_ALERT)
                    .isRead(false)
                    .sentAt(LocalDateTime.now())
                    .targetUrl(buildNotificationTargetUrl(alert))
                    .build();

            notificationRepository.save(notification);

            // Kullanıcının bildirim tercihlerine göre bildirimleri gönder
            sendNotificationsBasedOnPreferences(user, alert, "Araç Yaklaşıyor!", message);

            log.info("Geo uyarı bildirimi gönderildi: User={}, Alert={}, Route={}, Station={}",
                    user.getUsername(), alert.getId(), alert.getRoute().getName(), alert.getStation().getName());

        } catch (Exception e) {
            log.error("Geo uyarı bildirimi gönderilirken hata oluştu: User={}, Alert={}",
                    user.getUsername(), alert.getId(), e);
        }
    }

    private void sendNotificationsBasedOnPreferences(User user, GeoAlert alert, String title, String message) {
        if (user.getNotificationPreferences() == null) {
            // Varsayılan olarak push notification gönder
            sendPushNotification(user, title, message);
            return;
        }

        // Push notification kontrolü
        if (user.getNotificationPreferences().isPushEnabled() &&
                user.getNotificationPreferences().isFcmActive() &&
                user.getCurrentDeviceInfo() != null &&
                user.getCurrentDeviceInfo().getFcmToken() != null &&
                !user.getCurrentDeviceInfo().getFcmToken().isBlank()) {

            sendPushNotification(user, title, message);
        }

        // SMS kontrolü
        if (user.getNotificationPreferences().isSmsEnabled()) {
            sendSmsNotification(user, alert, message);
        }

        // Email kontrolü
        if (user.getNotificationPreferences().isEmailEnabled()) {
            sendEmailNotification(user, alert, title, message);
        }
    }

    private void sendPushNotification(User user, String title, String message) {
        try {
            fcmService.sendNotificationToToken(user, title, message, NotificationType.GEO_ALERT, null);
            log.debug("Push notification başarıyla gönderildi: {}", user.getUsername());
        } catch (Exception e) {
            log.error("Push notification gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private void sendSmsNotification(User user, GeoAlert alert, String message) {
        try {
            // SMS servis entegrasyonu
            String smsMessage = formatSmsMessage(alert, message);

            // Telefon numarası kontrolü
            if (user.getProfileInfo() != null &&
                    user.getUserNumber() != null &&
                    !user.getUserNumber().isBlank()) {

                // SMS servisi burada çağrılacak
                // smsService.sendSms(user.getProfileInfo().getPhoneNumber(), smsMessage);

                log.debug("SMS bildirimi gönderildi: {} - Tel: {}",
                        user.getUsername(), user.getUserNumber());
            } else {
                log.warn("SMS gönderilemedi - telefon numarası bulunamadı: {}", user.getUsername());
            }

        } catch (Exception e) {
            log.error("SMS bildirimi gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private void sendEmailNotification(User user, GeoAlert alert, String title, String message) {
        try {
            // Email servis entegrasyonu
            String emailContent = formatEmailContent(alert, message);

            // Email adresi kontrolü
            if (user.getProfileInfo() != null &&
                    user.getProfileInfo().getEmail() != null &&
                    !user.getProfileInfo().getEmail().isBlank()) {

                // Email servisi burada çağrılacak
                // emailService.sendEmail(user.getProfileInfo().getEmail(), title, emailContent);

                log.debug("Email bildirimi gönderildi: {} - Email: {}",
                        user.getUsername(), user.getProfileInfo().getEmail());
            } else {
                log.warn("Email gönderilemedi - email adresi bulunamadı: {}", user.getUsername());
            }

        } catch (Exception e) {
            log.error("Email bildirimi gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private String buildNotificationTargetUrl(GeoAlert alert) {
        // Bildirimi açtığında kullanıcıyı ilgili sayfaya yönlendirecek URL
        return String.format("/app/routes/%d/stations/%d",
                alert.getRoute().getId(),
                alert.getStation().getId());
    }

    private String formatSmsMessage(GeoAlert alert, String message) {
        // SMS için kısa ve öz mesaj formatı
        return String.format("🚌 %s rotası %s durağı - %s plakalı araç yaklaşıyor! Detay: %s",
                alert.getRoute().getCode(),
                alert.getStation().getName(),
                alert.getTriggeredByBusPlate() != null ? alert.getTriggeredByBusPlate() : "Bilinmiyor",
                "CityCard App");
    }

    private String formatEmailContent(GeoAlert alert, String message) {
        // Email için detaylı mesaj formatı
        StringBuilder emailContent = new StringBuilder();
        emailContent.append("Merhaba,\n\n");
        emailContent.append("Oluşturduğunuz geo uyarı tetiklendi!\n\n");
        emailContent.append("📍 Uyarı Detayları:\n");
        emailContent.append("• Uyarı Adı: ").append(alert.getAlertName()).append("\n");
        emailContent.append("• Rota: ").append(alert.getRoute().getName()).append(" (").append(alert.getRoute().getCode()).append(")\n");
        emailContent.append("• Durak: ").append(alert.getStation().getName()).append("\n");

        if (alert.getTriggeredByBusPlate() != null) {
            emailContent.append("• Araç Plakası: ").append(alert.getTriggeredByBusPlate()).append("\n");
        }

        emailContent.append("• Bildirim Zamanı: ").append(LocalDateTime.now().toString()).append("\n\n");
        emailContent.append("Aracın durağa yaklaştığı tahmin edilmektedir. ");
        emailContent.append("Güncel konum bilgileri için CityCard uygulamasını kontrol edebilirsiniz.\n\n");
        emailContent.append("İyi yolculuklar dileriz!\n\n");
        emailContent.append("CityCard Ekibi");

        return emailContent.toString();
    }

    /**
     * Kullanıcının bildirim tercihlerini kontrol et
     */
    private boolean shouldSendNotification(User user, NotificationType type) {
        if (user.getNotificationPreferences() == null) {
            return true; // Varsayılan olarak gönder
        }

        switch (type) {
            case GEO_ALERT:
                return user.getNotificationPreferences().isPushEnabled();
            default:
                return true;
        }
    }

    /**
     * Bildirim gönderme durumunu loglama
     */
    private void logNotificationAttempt(User user, String notificationType, boolean success, String reason) {
        if (success) {
            log.info("Bildirim başarılı - User: {}, Type: {}", user.getUsername(), notificationType);
        } else {
            log.warn("Bildirim başarısız - User: {}, Type: {}, Reason: {}",
                    user.getUsername(), notificationType, reason);
        }
    }
}