package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusNotFoundException extends BusinessException {
    public BusNotFoundException( ) {
        super("Otobüs bulunamadı");
    }
}
