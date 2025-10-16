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
public class AutoTopUpStatsDTO {

    private Long userId;
    private String username;
    private int totalActiveConfigs;
    private int totalInactiveConfigs;
    private int totalSuccessfulTopUps;
    private int totalFailedTopUps;
    private BigDecimal totalAmountTopUpped;
    private LocalDateTime lastTopUpDate;
    private LocalDateTime firstTopUpDate;
}