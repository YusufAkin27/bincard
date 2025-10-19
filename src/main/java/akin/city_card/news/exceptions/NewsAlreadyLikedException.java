package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NewsAlreadyLikedException extends BusinessException {
    public NewsAlreadyLikedException() {
        super("Haber zaten beğenilmiş");
    }
}
