package akin.city_card.security.exception;

public class UserDeletedException extends BusinessException {
    public UserDeletedException() {
        super("Kullanıcı silinmiş.");
    }
}
