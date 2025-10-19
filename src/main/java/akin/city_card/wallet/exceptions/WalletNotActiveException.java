package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class WalletNotActiveException extends BusinessException {
    public WalletNotActiveException() {
        super("cüzdan aktif değil");
    }
}
