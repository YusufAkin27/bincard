package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class EmailRequiredException extends BusinessException {
    public EmailRequiredException() {
        super("Email boş olamaz.");
    }
}
