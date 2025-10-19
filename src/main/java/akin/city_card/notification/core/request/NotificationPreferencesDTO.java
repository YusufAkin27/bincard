package akin.city_card.notification.core.request;

import lombok.Data;

@Data
public class NotificationPreferencesDTO {

    private boolean pushEnabled;
    private boolean smsEnabled;
    private boolean emailEnabled;
    private Integer notifyBeforeMinutes;
    private boolean fcmActive;
}
