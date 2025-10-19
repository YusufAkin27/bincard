package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PhoneNumberRequiredException extends BusinessException {
    public PhoneNumberRequiredException() {
        super("Telefon numarası boş olamaz.");
    }
}
