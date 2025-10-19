package akin.city_card.security.exception;

public class CancelledVerificationCodeException extends BusinessException {
    public CancelledVerificationCodeException() {
        super("Kod çok fazla yanlış girildiği için iptal edildi.");
    }
}
