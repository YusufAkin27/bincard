package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InsufficientBalanceException extends BusinessException {

    public InsufficientBalanceException() {
        super("Yetersiz bakiye");
    }
}
