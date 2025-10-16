package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VerificationCodeNotFoundException extends BusinessException {
    public VerificationCodeNotFoundException() {
        super("Doğrulama kodu bulunamadı");
    }
}
