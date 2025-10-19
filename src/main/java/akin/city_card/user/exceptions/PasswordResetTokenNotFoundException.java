package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PasswordResetTokenNotFoundException extends BusinessException {
    public PasswordResetTokenNotFoundException() {
        super("Şifre sıfırlama bağlantısı bulunamadı ");
    }
}
