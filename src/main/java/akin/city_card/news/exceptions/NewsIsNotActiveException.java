package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NewsIsNotActiveException extends BusinessException {

    public NewsIsNotActiveException(String message) {
        super(message + " Haber aktif değil");
    }
}
