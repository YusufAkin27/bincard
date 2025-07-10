package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ReportStatsDTO {
    private long totalReports;
    private long openReports;
    private long inReviewReports;
    private long resolvedReports;
    private long rejectedReports;
    private long cancelledReports;
    private long deletedReports;
    private long archivedReports;
    private long activeReports;
    
    // Category-based stats
    private long lostItemReports;
    private long driverComplaintReports;
    private long cardIssueReports;
    private long serviceDelayReports;
    private long otherReports;
    
    // Time-based stats
    private long reportsThisMonth;
    private long reportsThisWeek;
    private long reportsToday;
    
    // Response stats
    private long totalResponses;
    private long avgResponseTime; // in hours
    private double avgRating;
}