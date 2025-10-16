package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidShiftTypeException extends BusinessException {
    public InvalidShiftTypeException(String shift) {
        super("Geçersiz vardiya tipi: " + shift + ". Geçerli değerler: DAYTIME, NIGHT");
    }
}