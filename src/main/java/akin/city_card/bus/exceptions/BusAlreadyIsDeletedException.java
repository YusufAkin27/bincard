package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusAlreadyIsDeletedException extends BusinessException {
    public BusAlreadyIsDeletedException() {
        super("Otobus zaten silinmiş");
    }
}
