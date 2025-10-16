package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VerificationCodeCancelledException extends BusinessException {
    public VerificationCodeCancelledException() {
        super("Bu doğrulama kodu iptal edilmiş.");
    }
}
