package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidNationalIdFormatException extends BusinessException {
    public InvalidNationalIdFormatException() {
        super("Geçersiz kimlik formatı");
    }
}
