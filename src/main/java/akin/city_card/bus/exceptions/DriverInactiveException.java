package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverInactiveException extends BusinessException {

    public DriverInactiveException(Long id) {
        super("Şoför aktif değil. ID: " + id);
    }
}
