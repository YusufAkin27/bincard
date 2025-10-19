package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class IncorrectCurrentPasswordException extends BusinessException {
    public IncorrectCurrentPasswordException() {
        super("\"Mevcut şifre hatalı.\"");
    }
}
