package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class EmailMismatchException extends BusinessException {
    public EmailMismatchException() {
        super("E-posta adresi eşleşmiyor.");
    }
}
