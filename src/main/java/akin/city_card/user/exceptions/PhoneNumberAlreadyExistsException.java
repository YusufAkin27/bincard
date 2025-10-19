package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PhoneNumberAlreadyExistsException extends BusinessException {
    public PhoneNumberAlreadyExistsException() {
        super("Bu telefon numarasıyla zaten aktif bir kullanıcı mevcut.");
    }
}
