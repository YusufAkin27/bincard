package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DriverAlreadyExistsException extends BusinessException {
    public DriverAlreadyExistsException(String field, String value) {
        super("Bu " + field + " ile kayıtlı sürücü zaten mevcut: " + value);
    }
}