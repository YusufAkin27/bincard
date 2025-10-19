package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class EmailAlreadyExistsException extends BusinessException {
    public EmailAlreadyExistsException() {
        super("Bu email adresi zaten kullanımda.");
    }
}
