package akin.city_card.wallet.core.response;

import akin.city_card.wallet.model.Currency;
import akin.city_card.wallet.model.WalletStatus;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class WalletDTO {

    private Long walletId;

    private Long userId;

    private Currency currency;

    private BigDecimal balance;

    private WalletStatus status;

    private String activeTransferCode;

    private LocalDateTime transferCodeExpiresAt;

    private int totalTransactionCount;

    private LocalDateTime createdAt;

    private LocalDateTime lastUpdated;
}
