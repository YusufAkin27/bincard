package akin.city_card.bus.core.request;

import akin.city_card.buscard.model.CardType;
import lombok.Data;

@Data
public class RideRequest {
    private Long cardId;
    private CardType cardType;
}
