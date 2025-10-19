package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardNotActiveException extends BusinessException {
    public BusCardNotActiveException( ) {
        super("Otobüs kartı aktif değil");
    }
}
