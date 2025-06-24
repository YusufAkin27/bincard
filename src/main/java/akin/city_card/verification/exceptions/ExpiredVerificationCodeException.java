package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ExpiredVerificationCodeException extends BusinessException {
    public ExpiredVerificationCodeException() {
        super("Doğrulama kodunun süresi dolmuş.");
    }
}
