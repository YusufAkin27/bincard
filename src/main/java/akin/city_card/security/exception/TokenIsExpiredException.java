package akin.city_card.security.exception;

public class TokenIsExpiredException extends BusinessException {

    public TokenIsExpiredException() {
        super("Token  süresi dolmuş");
    }
}
