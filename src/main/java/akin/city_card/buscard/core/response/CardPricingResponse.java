package akin.city_card.buscard.core.response;

import akin.city_card.buscard.model.CardType;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class CardPricingResponse {
    private Long id;
    private CardType cardType;
    private BigDecimal price;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}