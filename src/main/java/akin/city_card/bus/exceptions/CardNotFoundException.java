package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CardNotFoundException extends BusinessException {

    public CardNotFoundException(Long cardId) {
        super(cardId + "Kart bulunamadı");
    }
}
