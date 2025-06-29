package akin.city_card.security.exception;

import akin.city_card.bus.model.Bus;

public class InvalidVerificationCodeException extends BusinessException {
    public InvalidVerificationCodeException( ) {
        super("Doğrulama kodu geçersiz.");
    }
}
