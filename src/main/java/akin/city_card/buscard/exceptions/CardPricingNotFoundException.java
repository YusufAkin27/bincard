package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CardPricingNotFoundException extends BusinessException {

    public CardPricingNotFoundException() {
        super("Kart fiyatlandırma bulunamadı");
    }
}
