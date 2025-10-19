package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordsDoNotMatchException extends BusinessException {
    public PasswordsDoNotMatchException() {
        super("Şifreler eşleşmiyor ");
    }
}
