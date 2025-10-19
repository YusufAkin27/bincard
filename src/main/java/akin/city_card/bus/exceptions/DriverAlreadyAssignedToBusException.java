package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverAlreadyAssignedToBusException extends BusinessException {

    public DriverAlreadyAssignedToBusException(Long driverId) {
        super("Şoför zaten başka bir aktif otobüse atanmış. ID: " + driverId);
    }
}
