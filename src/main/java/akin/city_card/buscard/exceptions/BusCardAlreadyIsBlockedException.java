package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardAlreadyIsBlockedException extends BusinessException {
    public BusCardAlreadyIsBlockedException( ) {
        super("Otobüs kartı zaten engellenmiş");
    }
}
