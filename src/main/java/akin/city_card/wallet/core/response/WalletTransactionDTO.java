package akin.city_card.wallet.core.response;

import akin.city_card.wallet.model.TransactionStatus;
import akin.city_card.wallet.model.TransactionType;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class WalletTransactionDTO {

    private Long id;

    private BigDecimal amount;

    private TransactionType type;

    private TransactionStatus status;

    private LocalDateTime timestamp;

    private String description;

    private String externalReference;

    private Long userId;

}
