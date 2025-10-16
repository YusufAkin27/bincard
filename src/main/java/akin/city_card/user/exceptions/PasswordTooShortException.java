package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordTooShortException extends BusinessException {
    public PasswordTooShortException() {
        super("Şifre 6 karakter olmalıdır.");
    }
}
