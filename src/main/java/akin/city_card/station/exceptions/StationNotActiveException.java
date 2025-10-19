package akin.city_card.station.exceptions;

import akin.city_card.security.exception.BusinessException;

public class StationNotActiveException extends BusinessException {
    public StationNotActiveException() {
        super("Durak aktif değil");
    }
}
