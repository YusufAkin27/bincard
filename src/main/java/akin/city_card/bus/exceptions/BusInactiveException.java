package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusInactiveException extends BusinessException {

    public BusInactiveException(Long busId) {
        super("Otobüs aktif değil ID: " + busId);
    }
}
