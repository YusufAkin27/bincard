package akin.city_card.superadmin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ThisTelephoneAlreadyUsedException extends BusinessException {
    public ThisTelephoneAlreadyUsedException() {
        super("Bu telefon zaten kullanılıyor");
    }
}
