package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardAlreadyExistsException extends BusinessException {
    public BusCardAlreadyExistsException(String uid) {
        super("Bu kart zaten kayıtlı: " + uid);
    }
}
