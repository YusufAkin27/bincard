package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class TransactionCounterException extends BusinessException {
    public TransactionCounterException( ) {
        super("tx counter hatası");
    }
}
