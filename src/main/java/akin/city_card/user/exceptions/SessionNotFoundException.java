package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SessionNotFoundException extends BusinessException {
    public SessionNotFoundException() {
        super("Aktif oturum (refresh token) bulunamadı.");
    }
}
