package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SamePasswordException extends BusinessException {
    public SamePasswordException() {
        super("same password");
    }
}
