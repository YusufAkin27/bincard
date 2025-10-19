package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidDateRangeException extends BusinessException {
    public InvalidDateRangeException() {
        super("Başlangıç tarihi bitiş tarihinden sonra olamaz.");
    }
}