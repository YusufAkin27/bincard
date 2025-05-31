package akin.city_card.security.exception;

public class NotFoundUserException extends BusinessException {
    public NotFoundUserException() {
        super("kullanıcı bulunamadı");
    }
}
