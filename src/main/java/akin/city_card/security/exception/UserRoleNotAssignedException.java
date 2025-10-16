package akin.city_card.security.exception;

public class UserRoleNotAssignedException extends BusinessException {
    public UserRoleNotAssignedException() {
        super("Kullanıcıya herhangi bir rol atanmamış.");
    }
}
