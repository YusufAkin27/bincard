package akin.city_card.report.core.response;

import akin.city_card.report.core.response.AdminReportResponseDTO;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AdminReportDTO {
    private Long id;
    private Long userId;
    private String userName;
    private ReportCategory category;
    private String message;
    private List<String> photoUrls;
    private List<AdminReportResponseDTO> responses;
    private ReportStatus status;
    private LocalDateTime createdAt;
    private boolean isActive;
}
