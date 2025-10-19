package akin.city_card.security.exception;

public class VerificationCodeStillValidException extends BusinessException {
    public VerificationCodeStillValidException() {
        super("Doğrulama kodu hâlâ geçerli, lütfen bekleyin.");
    }
}
