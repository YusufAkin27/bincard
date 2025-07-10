package akin.city_card.feedback.core.converter;

import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.Feedback;
import org.springframework.stereotype.Component;

@Component
public class FeedbackConverterImpl implements FeedbackConverter {
    @Override
    public FeedbackDTO toDTO(Feedback feedback) {
        return FeedbackDTO.builder()
                .id(feedback.getId())
                .type(feedback.getType())
                .message(feedback.getMessage())
                .photoUrl(feedback.getPhotoUrl())
                .source(feedback.getSource())
                .submittedAt(feedback.getSubmittedAt())
                .updatedAt(feedback.getUpdatedAt())
                .subject(feedback.getSubject())
                .userNumber(feedback.getUser().getUserNumber())
                .build();
    }
}
