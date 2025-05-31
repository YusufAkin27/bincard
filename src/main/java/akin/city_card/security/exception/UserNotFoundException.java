package akin.city_card.security.exception;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException() {
        super("Kullanıcı bulunamadı");
    }
}
