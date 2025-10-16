package akin.city_card.security.exception;

public class RefreshTokenExpiredException extends BusinessException {
    public RefreshTokenExpiredException() {
        super("Yenileme Token süresi dolmuş");
    }
}
