package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UserIsDeletedException extends BusinessException {

    public UserIsDeletedException() {
        super("Kullanıcı hesabı silinmiş");
    }
}
