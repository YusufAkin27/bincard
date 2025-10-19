package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class RouteDirectionNotFoundException extends BusinessException {
    public RouteDirectionNotFoundException() {
        super("Rota yönü bulunamadı");
    }
}
