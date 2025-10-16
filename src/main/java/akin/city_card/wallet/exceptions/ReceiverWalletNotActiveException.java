package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReceiverWalletNotActiveException extends BusinessException {
    public ReceiverWalletNotActiveException() {
        super("Alıcının cüzdanı aktif değil");
    }
}
