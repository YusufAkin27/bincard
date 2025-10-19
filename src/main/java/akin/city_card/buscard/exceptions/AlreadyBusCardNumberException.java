package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AlreadyBusCardNumberException extends BusinessException {
    public AlreadyBusCardNumberException( ) {
        super("Bu kart numarası zaten kullanılıyor");
    }
}
