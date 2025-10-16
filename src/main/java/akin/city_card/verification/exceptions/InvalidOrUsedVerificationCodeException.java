package akin.city_card.verification.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidOrUsedVerificationCodeException extends BusinessException {
    public InvalidOrUsedVerificationCodeException() {
        super("Invalid verification code");
    }
}
