package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class RouteStationNodeNotFoundException extends BusinessException {
    public RouteStationNodeNotFoundException() {
        super("Rota durakları bulunamadı");
    }
}
