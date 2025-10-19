package akin.city_card.security.exception;

public class UserNotActiveException extends BusinessException {
    public UserNotActiveException() {
        super("Kullanıcı aktif değil.");
    }
}
