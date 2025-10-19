package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UnderageUserException extends BusinessException {
    public UnderageUserException() {
        super("Kullanıcı en az 18 yaşında olmalıdır.");
    }
}
