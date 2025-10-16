package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InsufficientFundsException extends BusinessException {
    public InsufficientFundsException() {
        super("Bakiye yetersiz");
    }
}
