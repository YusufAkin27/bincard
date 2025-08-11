package akin.city_card.report.core.request;

import akin.city_card.report.model.ReportCategory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateReportRequest {
    private ReportCategory category;
    private String initialMessage;
}