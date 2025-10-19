package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordResetTokenIsUsedException extends BusinessException {
    public PasswordResetTokenIsUsedException() {
        super("Şifre sıfırlama anahtarın kullanılmış");
    }
}
