package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidEmailFormatException extends BusinessException {
    public InvalidEmailFormatException() {
        super("Geçersiz email formatı");
    }
}
