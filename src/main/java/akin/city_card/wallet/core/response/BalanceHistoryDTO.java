package akin.city_card.wallet.core.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class BalanceHistoryDTO {
    private LocalDateTime date;
    private BigDecimal balance;
}
