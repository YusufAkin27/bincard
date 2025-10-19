package akin.city_card.user.core.request;

import lombok.Data;

@Data
public class LowBalanceAlertRequest {
    private Long busCardId;
    private Double lowBalance;
}
