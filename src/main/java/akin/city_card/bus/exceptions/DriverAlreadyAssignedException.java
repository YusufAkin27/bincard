package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverAlreadyAssignedException extends BusinessException {

    public DriverAlreadyAssignedException(Long driverId) {
        super(driverId + " sürücü zaten atanmış");
    }
}
