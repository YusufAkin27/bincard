package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordSameAsOldException extends BusinessException {

    public PasswordSameAsOldException() {
        super("Yeni şifre eski şifreyle aynı olamaz.");
    }
}
