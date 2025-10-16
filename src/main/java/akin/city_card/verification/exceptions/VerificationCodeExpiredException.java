package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VerificationCodeExpiredException extends BusinessException {
    public VerificationCodeExpiredException() {
        super("Doğrulama kodunun süresi dolmuş.");
    }
}
