package akin.city_card.driver.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DriverPenaltyDto {
    private Long id;
    private String reason;
    private LocalDate date;
    private BigDecimal amount;
}
