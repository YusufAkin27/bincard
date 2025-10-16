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
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ReportChatDTO {
    private Long reportId;
    private SimpleUserDTO user;
    private ReportCategory category;
    private String initialMessage;
    private ReportStatus status;
    private ReportPriority priority;
    private LocalDateTime createdAt;
    private LocalDateTime lastMessageAt;
    private MessageSender lastMessageSender;
    private int unreadCount;
    private List<MessageDTO> messages;

    // Admin fields
    private String assignedAdmin;
    private String adminNotes;
    private boolean isAssigned;
    private boolean isArchived;

    // Satisfaction fields
    private boolean canRate;
    private boolean isRated;
    private Integer satisfactionRating;
    private String satisfactionComment;
    private LocalDateTime satisfactionRatedAt;
}