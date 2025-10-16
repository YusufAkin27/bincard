package akin.city_card.notification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class YouCanNotDeleteTheNotification extends BusinessException {
    public YouCanNotDeleteTheNotification() {
        super("\"Bu bildirimi silmeye yetkiniz yok.\"");
    }
}
