package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VerificationCodeTypeMismatchException extends BusinessException {
    public VerificationCodeTypeMismatchException() {
        super("Kod e-posta doğrulama için geçerli değil.");
    }
}
