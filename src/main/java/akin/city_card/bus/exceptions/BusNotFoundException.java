package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusNotFoundException extends BusinessException {
    public BusNotFoundException(Long busId) {
        super(busId + " Otobüs bulunamadı");
    }
}
