package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NameAndSurnameAreWrongException extends BusinessException {
    public NameAndSurnameAreWrongException() {
        super("Ad soyad hatalı");
    }
}
