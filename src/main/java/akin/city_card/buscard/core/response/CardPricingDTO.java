package akin.city_card.buscard.core.response;

import akin.city_card.buscard.model.CardType;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class CardPricingDTO {
    private CardType cardType;
    private BigDecimal price;
}
