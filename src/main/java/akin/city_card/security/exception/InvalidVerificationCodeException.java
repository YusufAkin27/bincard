package akin.city_card.security.exception;

public class InvalidVerificationCodeException extends BusinessException {
    public InvalidVerificationCodeException() {
        super("Doğrulama kodu geçersiz.");
    }
}
