package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class TransferNotFoundException extends BusinessException {
    public TransferNotFoundException() {
        super("Transfer bulunamadı");
    }
}
