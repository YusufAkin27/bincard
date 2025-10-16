package akin.city_card.report.core.response;

import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPriority;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReportStatsDTO {
    private long totalReports;
    private long openReports;
    private long inReviewReports;
    private long resolvedReports;
    private long rejectedReports;
    private long cancelledReports;
    private long unassignedReports;
    private long totalRatedReports;
    private double averageSatisfactionRating;
    private double averageResolutionTimeMinutes;

    // Category breakdown
    private Map<ReportCategory, Long> reportsByCategory;

    // Priority breakdown
    private Map<ReportPriority, Long> reportsByPriority;

    // Monthly trends
    private List<MonthlyReportCount> monthlyTrends;
}
