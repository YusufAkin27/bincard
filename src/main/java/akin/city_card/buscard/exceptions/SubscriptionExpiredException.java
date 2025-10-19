package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SubscriptionExpiredException extends BusinessException {
    public SubscriptionExpiredException( ) {
        super("Abonman süresi dolmuş");
    }
}
