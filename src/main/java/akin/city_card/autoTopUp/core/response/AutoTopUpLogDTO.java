package akin.city_card.autoTopUp.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AutoTopUpLogDTO {

    private Long id;
    private Long configId;
    private String busCardNumber;
    private LocalDateTime timestamp;
    private BigDecimal amount;
    private boolean success;
    private String failureReason;
    private BigDecimal cardBalanceBefore;
    private BigDecimal cardBalanceAfter;
    private BigDecimal walletBalanceBefore;
    private BigDecimal walletBalanceAfter;
}
