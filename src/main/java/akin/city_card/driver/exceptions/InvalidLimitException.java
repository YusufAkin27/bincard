package akin.city_card.driver.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidLimitException extends BusinessException {
    public InvalidLimitException(int min, int max) {
        super("Limit " + min + "-" + max + " arasında olmalıdır.");
    }
}