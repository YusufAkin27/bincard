package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverNotFoundException extends BusinessException {

    public DriverNotFoundException() {
        super("sürücü bulunamadı");
    }
}
