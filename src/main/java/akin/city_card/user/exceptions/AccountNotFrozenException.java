package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AccountNotFrozenException extends BusinessException {
    public AccountNotFrozenException() {
        super("Hesabınız donmuş durumda değil.");
    }
}
