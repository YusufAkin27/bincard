package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SubscriptionNotFoundException extends BusinessException {
    public SubscriptionNotFoundException( ) {
        super("Abonman bulunamadı");
    }
}
