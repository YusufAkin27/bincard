package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverDocumentNotFoundException extends BusinessException {
    public DriverDocumentNotFoundException(Long id) {
        super("Sürücü belgesi bulunamadı. ID: " + id);
    }
}