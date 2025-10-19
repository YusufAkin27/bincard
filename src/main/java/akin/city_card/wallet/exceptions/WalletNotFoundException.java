package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class WalletNotFoundException extends BusinessException {
    public WalletNotFoundException() {
        super("cüzdan bulunamadı");
    }
}
