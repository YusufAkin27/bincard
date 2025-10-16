package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class WalletIsEmptyException extends BusinessException {
    public WalletIsEmptyException() {
        super("cüzdan henüz oluşturulmamış");
    }
}
