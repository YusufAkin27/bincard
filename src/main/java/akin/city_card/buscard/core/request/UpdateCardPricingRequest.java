package akin.city_card.buscard.core.request;

import akin.city_card.buscard.model.CardType;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class UpdateCardPricingRequest {
    @NotNull(message = "Card type is required")
    private CardType cardType;

    @NotNull(message = "Price is required")
    private BigDecimal price;
}