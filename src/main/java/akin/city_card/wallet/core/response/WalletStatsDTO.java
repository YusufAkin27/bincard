package akin.city_card.wallet.core.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

@Data
@Builder
public class WalletStatsDTO {
    private int totalTransactionCount;
    private BigDecimal totalDepositAmount;
    private BigDecimal totalWithdrawAmount;
    private BigDecimal netChange; // totalDeposit - totalWithdraw
}
