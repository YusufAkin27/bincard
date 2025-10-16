package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AutoTopUpConfigNotFoundException extends BusinessException {
    public AutoTopUpConfigNotFoundException() {
        super("Otomatik ödeme talimatı bulunamadı");
    }
}
