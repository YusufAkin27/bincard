package akin.city_card.report.core.response;

import akin.city_card.report.model.MessageSender;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPriority;
import akin.city_card.report.model.ReportStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminReportDTO {
    private Long reportId;
    private String userNumber;
    private String userName;
    private ReportCategory category;
    private String initialMessage;
    private ReportStatus status;
    private ReportPriority priority;
    private LocalDateTime createdAt;
    private LocalDateTime lastMessageAt;
    private MessageSender lastMessageSender;
    private int unreadByAdmin;
    private boolean isAssigned;
    private String assignedAdminUsername;
    private LocalDateTime assignedAt;
    private String adminNotes;
    private boolean isArchived;
    private boolean isDeleted;

    // Rating info
    private boolean canRate;
    private boolean isRated;
    private Integer satisfactionRating;
    private String satisfactionComment;

    // Messages preview
    private List<MessageDTO> recentMessages;

    // Resolution info
    private LocalDateTime resolvedAt;
    private Long resolutionTimeMinutes;
}
