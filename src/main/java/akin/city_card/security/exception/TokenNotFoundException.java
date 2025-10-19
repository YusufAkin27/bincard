package akin.city_card.security.exception;

public class TokenNotFoundException extends BusinessException {
    public TokenNotFoundException() {
        super("Token bulunamadı.");
    }
}
