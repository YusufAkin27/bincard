package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CardInactiveException extends BusinessException {
    public CardInactiveException( ) {
        super("Bu kart aktif değil");
    }
}
