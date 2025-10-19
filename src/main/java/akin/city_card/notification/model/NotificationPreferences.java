package akin.city_card.notification.model;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NotificationPreferences {

    private boolean pushEnabled = true;
    private boolean smsEnabled = false;
    private boolean emailEnabled = false;

    // Belirli araç/rota için ne kadar süre önce bildirim gönderilsin (dakika)
    private Integer notifyBeforeMinutes = 5;

    // FCM token güncel mi
    private boolean fcmActive = true;
}
