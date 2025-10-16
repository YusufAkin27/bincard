package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InactiveCardException extends BusinessException {
    public InactiveCardException(String uid) {
        super("Kart aktif değil: " + uid);
    }
}