package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReceiverWalletNotFoundException extends BusinessException {
    public ReceiverWalletNotFoundException() {
        super("Alıcının cüzdanı bulunamadı");
    }
}
