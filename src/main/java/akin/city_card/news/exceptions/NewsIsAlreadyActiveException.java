package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NewsIsAlreadyActiveException extends BusinessException {

    public NewsIsAlreadyActiveException(String message) {
        super(message + "haber zaten aktif");
    }
}
