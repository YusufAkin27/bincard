package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidNewPasswordException extends BusinessException {
    public InvalidNewPasswordException() {
        super("Invalid New Password");
    }
}
