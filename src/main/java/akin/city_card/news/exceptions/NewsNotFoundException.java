package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NewsNotFoundException extends BusinessException {
    public NewsNotFoundException() {
        super("Haber bulunamadı");
    }
}
