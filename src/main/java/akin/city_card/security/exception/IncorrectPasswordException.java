package akin.city_card.security.exception;

public class IncorrectPasswordException extends BusinessException {
    public IncorrectPasswordException() {
        super("Hatalı şifre");
    }
}
