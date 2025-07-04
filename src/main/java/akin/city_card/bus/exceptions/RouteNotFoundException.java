package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;
import org.jetbrains.annotations.NotNull;

public class RouteNotFoundException extends BusinessException {

    public RouteNotFoundException(Long id) {
        super(id+"id li rota bulunamadı");
    }
}
