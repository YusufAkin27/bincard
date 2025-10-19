package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VerificationCodeAlreadyUsedException extends BusinessException {
    public VerificationCodeAlreadyUsedException() {
        super("Bu doğrulama kodu zaten kullanılmış.");
    }
}
