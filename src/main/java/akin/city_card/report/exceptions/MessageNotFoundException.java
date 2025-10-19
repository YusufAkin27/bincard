package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class MessageNotFoundException extends BusinessException {
    public MessageNotFoundException() {
        super("Mesaj buluanamadı");
    }
}
