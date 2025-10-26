package akin.city_card.buscard.core.request;

import lombok.Data;

import java.math.BigDecimal;

@Data
public class TopUpCardRequest {
    private String cardNumber;
    private BigDecimal amount;
}
