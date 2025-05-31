package akin.city_card.feedback.repository;

import akin.city_card.feedback.model.Feedback;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FeedBackRepository extends JpaRepository<Feedback,Long> {
}
