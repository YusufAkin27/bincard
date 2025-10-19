package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BirthDateRequiredException extends BusinessException {
    public BirthDateRequiredException() {
        super("Doğum tarihi belirtilmelidir.");
    }
}
