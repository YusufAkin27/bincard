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
public class DriverEarningSummaryDto {
    private Long driverId;
    private String driverUserNumber;
    private String fullName;
    private String busNumberPlate;
    private int totalTrips;
    private BigDecimal totalRevenue;
    private BigDecimal averageFare;
    private Double totalDistanceKm;
    private Double averageDistancePerTripKm;
    private LocalDate startDate;
    private LocalDate endDate;
}

