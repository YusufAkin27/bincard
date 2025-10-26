package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class MinumumTopUpAmountException extends BusinessException {
    public MinumumTopUpAmountException( ) {
        super("Minimum 20 lira yükleyebilirsiniz");
    }
}
