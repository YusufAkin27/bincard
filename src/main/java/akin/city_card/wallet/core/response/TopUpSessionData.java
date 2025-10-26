package akin.city_card.wallet.core.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.math.BigDecimal;

@Data
@AllArgsConstructor
public class TopUpSessionData {
    private String username;
    private String cardNumber;
    private BigDecimal amount;
}
