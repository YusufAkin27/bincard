package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusNotAtAnyStationException extends BusinessException {
    public BusNotAtAnyStationException() {
        super("Otobüs Herhangi Bir İstasyonda Değil");
    }
}
