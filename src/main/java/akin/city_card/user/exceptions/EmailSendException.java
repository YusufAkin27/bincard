package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class EmailSendException extends BusinessException {
    public EmailSendException() {
        super("Email gönderilemedi");
    }
}
