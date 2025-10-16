package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UserIsNotPhoneVerifyException extends BusinessException {
    public UserIsNotPhoneVerifyException() {
        super("Telefon numarası doğrulanmamış");
    }
}
