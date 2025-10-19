package akin.city_card.station.exceptions;

import akin.city_card.security.exception.BusinessException;

public class StationNotFoundException extends BusinessException {
    public StationNotFoundException() {
        super("durak bulunamadı");
    }
}
