package akin.city_card.news.exceptions;

import akin.city_card.security.exception.BusinessException;

public class OutDatedNewsException extends BusinessException {
    public OutDatedNewsException() {
        super("Tarihi geçmiş haber");
    }
}
