package akin.city_card.feedback.core.response;

import akin.city_card.feedback.model.FeedbackType;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class FeedbackDTO {
    private Long id;
    private String subject;
    private String message;
    private FeedbackType type;
    private String source;
    private LocalDateTime submittedAt;
    private LocalDateTime updatedAt;
    private String photoUrl;

    // User bilgileri (eğer giriş yapmış kullanıcıysa)
    private Long userId;
    private String userNumber; // Kullanıcı numarası (gizlilik için kısmi gösterim yapılabilir)

    // Anonim kullanıcı için iletişim bilgileri
    private String contactEmail;
    private String contactName;
    private String contactPhone;

    // Feedback'in türü
    private Boolean isAnonymous;

    // Effective (etkili) değerler - görüntüleme için
    private String effectiveContactName;
    private String effectiveContactEmail;
}