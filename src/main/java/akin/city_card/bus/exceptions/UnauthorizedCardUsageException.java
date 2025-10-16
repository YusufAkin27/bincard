package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UnauthorizedCardUsageException extends BusinessException {
    public UnauthorizedCardUsageException() {
        super("yetkisiz kart kullanımı");
    }
}
