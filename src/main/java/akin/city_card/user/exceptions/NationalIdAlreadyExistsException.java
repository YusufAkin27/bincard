package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NationalIdAlreadyExistsException extends BusinessException {
    public NationalIdAlreadyExistsException() {
        super("Bu T.C. kimlik numarası zaten kullanımda.");
    }
}
