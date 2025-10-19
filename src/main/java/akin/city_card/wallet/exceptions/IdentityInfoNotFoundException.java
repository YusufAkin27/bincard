package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class IdentityInfoNotFoundException extends BusinessException {
    public IdentityInfoNotFoundException() {
        super("Kimlik bilgisi bulunamadı");
    }
}
