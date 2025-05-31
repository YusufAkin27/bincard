package akin.city_card.security.exception;

public class InvalidRefreshTokenException extends BusinessException {
    public InvalidRefreshTokenException() {
        super("Geçersiz yenileme tokenı");
    }
}
