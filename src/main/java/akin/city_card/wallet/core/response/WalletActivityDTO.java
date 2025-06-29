package akin.city_card.wallet.core.response;

import akin.city_card.wallet.model.WalletActivityType;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class WalletActivityDTO {

    private Long id;

    private WalletActivityType activityType;

    private Long transactionId;

    private Long transferId;

    private LocalDateTime activityDate;

    private String description;
}
