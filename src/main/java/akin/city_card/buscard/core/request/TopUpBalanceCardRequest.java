package akin.city_card.buscard.core.request;

import lombok.Data;

import java.math.BigDecimal;

@Data
public class TopUpBalanceCardRequest {
private String uid;
private BigDecimal amount;
}
