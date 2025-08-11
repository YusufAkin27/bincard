package akin.city_card.report.core.response;

import akin.city_card.report.model.MessageSender;
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
public class ReportChatDTO {
    private Long id;
    private SimpleUserDTO user;
    private ReportCategory category;
    private String initialMessage;
    private ReportStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime lastMessageAt;
    private MessageSender lastMessageSender;
    private String lastMessage;
    private int unreadCount; // Current user'ın okunmamış mesaj sayısı
    private int totalMessages;
    private boolean isActive;
    private boolean archived;
    private boolean deleted; // ===== YENİ EKLENEN =====
    private List<MessageDTO> recentMessages; // Son 3-5 mesaj önizlemesi
    
    // ===== YENİ EKLENEN MEMNUNIYET ALANLARI =====
    private SatisfactionRatingDTO satisfactionRating;
    private boolean canBeRated; // Puanlanabilir mi?
}