package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class IdentityVerificationRequestNotFoundException extends BusinessException {
    public IdentityVerificationRequestNotFoundException() {
        super("Kimlik doğrulama isteği bulunamadı");
    }
}
