package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UnauthorizedAreaException extends BusinessException {
    public UnauthorizedAreaException() {
        super("Yetkisiz alan hatası");
    }
}
