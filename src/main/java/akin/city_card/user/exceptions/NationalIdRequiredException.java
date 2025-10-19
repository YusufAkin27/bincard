package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NationalIdRequiredException extends BusinessException {
    public NationalIdRequiredException() {
        super("Kimlik numarası boş olamaz.");
    }
}
