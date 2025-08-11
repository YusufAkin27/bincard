package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ReportStatsDTO {
    
    // Mevcut stat'lar
    private long totalReports;
    private long openReports;
    private long inReviewReports;
    private long resolvedReports;
    private long rejectedReports;
    private long cancelledReports;
    private long deletedReports;
    private long archivedReports;
    private long activeReports;
    private long lostItemReports;
    private long driverComplaintReports;
    private long cardIssueReports;
    private long serviceDelayReports;
    private long otherReports;
    private long reportsToday;
    private long reportsThisWeek;
    private long reportsThisMonth;
    
    private SatisfactionStatsDTO satisfactionStats;
}