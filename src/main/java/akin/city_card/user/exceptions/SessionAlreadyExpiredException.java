package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SessionAlreadyExpiredException extends BusinessException {
    public SessionAlreadyExpiredException() {
        super("Oturum zaten süresi dolmuş.");
    }
}
