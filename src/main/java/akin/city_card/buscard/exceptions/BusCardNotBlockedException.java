package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardNotBlockedException extends BusinessException {
    public BusCardNotBlockedException( ) {
        super("Otobüs kartı engellenmemiş");
    }
}
