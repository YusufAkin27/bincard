package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordResetTokenExpiredException extends BusinessException {
    public PasswordResetTokenExpiredException() {
        super("Şifre sıfırlama anahtarının süresi dolmuş");
    }
}
