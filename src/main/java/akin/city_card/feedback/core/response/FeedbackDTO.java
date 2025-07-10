package akin.city_card.feedback.core.response;

import akin.city_card.feedback.model.FeedbackType;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class FeedbackDTO {


    private Long id;

    private String userNumber;

    private String subject;

    private String message;

    private FeedbackType type;

    private LocalDateTime submittedAt;

    private LocalDateTime updatedAt;

    private String source;

    private String photoUrl;
}
