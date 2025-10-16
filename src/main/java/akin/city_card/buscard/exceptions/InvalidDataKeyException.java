package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidDataKeyException extends BusinessException {
    public InvalidDataKeyException(String cardNumber) {
        super("Kart için data key geçersiz veya bozulmuş: " + cardNumber);
    }
}