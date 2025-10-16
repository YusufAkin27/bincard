package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NewsNotLikedException extends BusinessException {

    public NewsNotLikedException() {
        super("Haber zaten beğenilmemiş");
    }
}
