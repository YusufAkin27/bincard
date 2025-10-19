package akin.city_card.feedback.core.converter;

import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.Feedback;

public interface FeedbackConverter {
    FeedbackDTO toDTO(Feedback feedback);
}
