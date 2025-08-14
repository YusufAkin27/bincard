package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminSummaryDTO {
    private Long adminId;
    private String username;
    private String fullName;
    private long assignedReportsCount;
    private long resolvedReportsCount;
    private double averageSatisfactionRating;
    private double resolutionRate;
}