package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SatisfactionStatsDTO {
    private long totalRatedReports;
    private double averageRating;
    private long rating1Count;
    private long rating2Count;
    private long rating3Count;
    private long rating4Count;
    private long rating5Count;

    // Percentage calculations
    public double getRating1Percentage() {
        return totalRatedReports > 0 ? (double) rating1Count / totalRatedReports * 100 : 0.0;
    }

    public double getRating2Percentage() {
        return totalRatedReports > 0 ? (double) rating2Count / totalRatedReports * 100 : 0.0;
    }

    public double getRating3Percentage() {
        return totalRatedReports > 0 ? (double) rating3Count / totalRatedReports * 100 : 0.0;
    }

    public double getRating4Percentage() {
        return totalRatedReports > 0 ? (double) rating4Count / totalRatedReports * 100 : 0.0;
    }

    public double getRating5Percentage() {
        return totalRatedReports > 0 ? (double) rating5Count / totalRatedReports * 100 : 0.0;
    }
}