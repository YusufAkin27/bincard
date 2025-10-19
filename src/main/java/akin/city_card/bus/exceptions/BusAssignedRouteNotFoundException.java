package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusAssignedRouteNotFoundException extends BusinessException {
    public BusAssignedRouteNotFoundException() {
        super("Otobüse tanımlanmış rota bulunamadı");
    }
}
