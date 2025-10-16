package akin.city_card.driver.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DriverPerformanceDto {
    private Long totalDrivingHours;
    private Double totalDistanceDriven;
    private Long totalPassengersTransported;
    private BigDecimal totalEarnings;
    private Double averageRating;
}
