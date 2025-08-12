package akin.city_card.feedback.core.converter;

import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.Feedback;
import org.springframework.stereotype.Component;

@Component
public class FeedbackConverterImpl implements FeedbackConverter {
    public FeedbackDTO toDTO(Feedback feedback) {
        if (feedback == null) {
            return null;
        }

        return FeedbackDTO.builder()
                .id(feedback.getId())
                .subject(feedback.getSubject())
                .message(feedback.getMessage())
                .type(feedback.getType())
                .source(feedback.getSource())
                .submittedAt(feedback.getSubmittedAt())
                .updatedAt(feedback.getUpdatedAt())
                .photoUrl(feedback.getPhotoUrl())
                .userId(feedback.getUser() != null ? feedback.getUser().getId() : null)
                .userNumber(feedback.getUser() != null ? maskUserNumber(feedback.getUser().getUserNumber()) : null)
                .contactEmail(feedback.getContactEmail())
                .contactName(feedback.getContactName())
                .contactPhone(feedback.getContactPhone())
                .isAnonymous(feedback.getIsAnonymous())
                .effectiveContactName(feedback.getEffectiveContactName())
                .effectiveContactEmail(feedback.getEffectiveContactEmail())
                .build();
    }

    // Kullanıcı numarasını kısmen gizle (gizlilik için)
    private String maskUserNumber(String userNumber) {
        if (userNumber == null || userNumber.length() < 4) {
            return userNumber;
        }

        // İlk 3 ve son 2 karakteri göster, ortasını * ile gizle
        int length = userNumber.length();
        String start = userNumber.substring(0, 3);
        String end = userNumber.substring(length - 2);
        String middle = "*".repeat(Math.max(0, length - 5));

        return start + middle + end;
    }
}
