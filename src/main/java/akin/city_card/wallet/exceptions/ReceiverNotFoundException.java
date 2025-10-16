package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReceiverNotFoundException extends BusinessException {
    public ReceiverNotFoundException() {
        super("Alıcı bulunamadı");
    }
}
