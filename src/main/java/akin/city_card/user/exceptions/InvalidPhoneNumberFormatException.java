package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidPhoneNumberFormatException extends BusinessException {
    public InvalidPhoneNumberFormatException() {
        super("Geçersiz telefon formatı");
    }
}
