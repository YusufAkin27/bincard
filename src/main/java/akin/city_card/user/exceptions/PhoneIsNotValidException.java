package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PhoneIsNotValidException extends BusinessException {
    public PhoneIsNotValidException() {
        super("Geçerli bir telefon numarası giriniz");
    }
}
