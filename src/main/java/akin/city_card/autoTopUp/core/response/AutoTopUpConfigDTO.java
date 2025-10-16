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
public class AutoTopUpConfigDTO {

    private Long id;
    private Long busCardId;
    private String busCardNumber;
    private String busCardAlias;
    private BigDecimal threshold;
    private BigDecimal amount;
    private boolean active;
    private LocalDateTime lastTopUpAt;
    private LocalDateTime createdAt;
    private int totalTopUpCount;
    private BigDecimal totalTopUpAmount;
}
