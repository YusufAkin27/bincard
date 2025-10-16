package akin.city_card.location.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NoLocationFoundException extends BusinessException {
    public NoLocationFoundException() {
        super("Kullanıcının konum kaydı bulunamadı.");
    }
}
