package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class StationLocationNotFoundException extends BusinessException {
    public StationLocationNotFoundException() {
        super("durak konum bilgisi bulunamadı");
    }
}
