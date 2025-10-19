package akin.city_card.buscard.core.request;


import akin.city_card.buscard.model.CardType;

import java.math.BigDecimal;


public class CreateCardPricingRequest {
    private CardType cardType;
    private BigDecimal price;

    public CardType getCardType() {
        return cardType;
    }

    public void setCardType(CardType cardType) {
        this.cardType = cardType;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        if (price.compareTo(BigDecimal.ZERO) > 0) {
            this.price = price;
        } else {
            throw new IllegalArgumentException("Price must be greater than zero");
        }
    }
}
