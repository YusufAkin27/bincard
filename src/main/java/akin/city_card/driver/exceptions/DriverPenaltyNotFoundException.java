package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverPenaltyNotFoundException extends BusinessException {
    public DriverPenaltyNotFoundException(Long id) {
        super("Sürücü cezası bulunamadı. ID: " + id);
    }

    public DriverPenaltyNotFoundException() {
        super("Sürücü cezası bulunamadı.");
    }
}