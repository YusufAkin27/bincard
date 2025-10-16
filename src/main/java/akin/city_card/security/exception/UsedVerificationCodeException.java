package akin.city_card.security.exception;

public class UsedVerificationCodeException extends BusinessException {
    public UsedVerificationCodeException() {
        super("Doğrulama kodu zaten kullanılmış.");
    }
}
