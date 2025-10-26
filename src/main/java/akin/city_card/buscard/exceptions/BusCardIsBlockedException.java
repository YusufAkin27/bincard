package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardIsBlockedException extends BusinessException {
    public BusCardIsBlockedException( ) {
        super("bu kart bloklanmış");
    }
}
