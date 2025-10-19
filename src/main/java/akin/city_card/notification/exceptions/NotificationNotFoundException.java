package akin.city_card.notification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NotificationNotFoundException extends BusinessException {
    public NotificationNotFoundException() {
        super("Bildirim bulunamadı.");
    }
}
