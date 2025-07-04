package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;
import org.jetbrains.annotations.NotNull;

public class DriverNotFoundException extends BusinessException {

    public DriverNotFoundException( Long   driverId) {
        super(driverId+"sürücü bulunamadı");
    }
}
