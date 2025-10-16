package akin.city_card.report.core.request;

import akin.city_card.report.model.ReportPriority;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AssignReportRequest {
    @NotNull(message = "Report ID boş olamaz")
    private Long reportId;

    private ReportPriority priority;

    private String adminNotes;
}