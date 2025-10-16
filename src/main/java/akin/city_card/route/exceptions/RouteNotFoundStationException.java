package akin.city_card.route.exceptions;

import akin.city_card.security.exception.BusinessException;

public class RouteNotFoundStationException extends BusinessException {
    public RouteNotFoundStationException() {
        super("Rotanın içinde durak bulunamadı");
    }
}
