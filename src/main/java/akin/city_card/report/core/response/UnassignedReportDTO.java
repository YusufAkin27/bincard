package akin.city_card.report.core.response;

import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPriority;
import akin.city_card.report.model.ReportStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UnassignedReportDTO {
    private Long id;
    private String userFullName;
    private String userNumber;
    private ReportCategory category;
    private ReportPriority priority;
    private String initialMessage;
    private ReportStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime lastMessageAt;
    private int unreadByAdmin;
    private boolean isUrgent; // 24 saatten eski mi?
    private long hoursWaiting; // Kaç saattir bekliyor
    private int totalMessages;
}