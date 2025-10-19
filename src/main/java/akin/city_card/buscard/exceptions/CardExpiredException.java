package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CardExpiredException extends BusinessException {
    public CardExpiredException(String uid) {
        super("Kartın vize süresi dolmuş: " + uid);
    }
}