package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MonthlyReportCount {
    private int year;
    private int month;
    private long totalReports;
    private long resolvedReports;
    private double averageSatisfactionRating;
}