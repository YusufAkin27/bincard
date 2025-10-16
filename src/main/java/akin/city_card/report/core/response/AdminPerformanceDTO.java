package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminPerformanceDTO {
    private String adminUsername;
    private long totalAssignedReports;
    private long totalResolvedReports;
    private double averageResolutionTimeMinutes;
    private double averageSatisfactionRating;
    private long totalRatedReports;
    private double resolutionRate;

    // Time-based performance
    private double averageResponseTimeMinutes;
    private long reportsResolvedThisMonth;
    private long reportsResolvedThisWeek;

    // Quality metrics
    private long highSatisfactionCount; // 4-5 star ratings
    private long lowSatisfactionCount;  // 1-2 star ratings

    public double getHighSatisfactionRate() {
        return totalRatedReports > 0 ? (double) highSatisfactionCount / totalRatedReports * 100 : 0.0;
    }
}