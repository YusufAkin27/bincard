package akin.city_card.security.exception;

public class VerificationCooldownException extends BusinessException {

    public VerificationCooldownException(long remainingSeconds) {
        super("Lütfen tekrar denemeden önce " + remainingSeconds + " saniye bekleyin.");
    }
}
