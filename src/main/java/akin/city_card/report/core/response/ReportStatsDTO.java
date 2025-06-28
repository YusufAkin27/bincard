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
    private long todayReportCount;
    private String mostUsedCategory;
    private double averageResponseTimeInHours;
    private AdminReportResponseDTO mostRatedResponse;
}
