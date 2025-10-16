package akin.city_card.route.exceptions;

import akin.city_card.security.exception.BusinessException;

public class RouteNotActiveException extends BusinessException {
    public RouteNotActiveException() {
        super("Rota aktif değil");
    }
}
