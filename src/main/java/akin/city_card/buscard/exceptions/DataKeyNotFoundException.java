package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DataKeyNotFoundException extends BusinessException {
    public DataKeyNotFoundException(String cardNumber) {
        super("Kart için şifrelenmiş data key bulunamadı: " + cardNumber);
    }
}