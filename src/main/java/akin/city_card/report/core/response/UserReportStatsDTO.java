package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserReportStatsDTO {
    private long totalReports;
    private long openReports;
    private long inReviewReports;
    private long resolvedReports;
    private long rejectedReports;
    private long cancelledReports;
    private long ratedReports;
    private Double averageRatingGiven;
    private long reportsThisMonth;
    private long reportsThisWeek;
}