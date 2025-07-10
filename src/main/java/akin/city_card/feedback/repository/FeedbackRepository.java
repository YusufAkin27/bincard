package akin.city_card.feedback.repository;


import akin.city_card.feedback.model.Feedback;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface FeedbackRepository extends JpaRepository<Feedback, Long> {
    @Query(value = """
    SELECT f FROM Feedback f
    WHERE (:type IS NULL OR f.type = :type)
      AND (:source IS NULL OR f.source = :source)
      AND f.submittedAt BETWEEN :start AND :end
""",
            countQuery = """
    SELECT COUNT(f) FROM Feedback f
    WHERE (:type IS NULL OR f.type = :type)
      AND (:source IS NULL OR f.source = :source)
      AND f.submittedAt BETWEEN :start AND :end
""")
    Page<Feedback> findFiltered(
            @Param("type") String type,
            @Param("source") String source,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end,
            Pageable pageable
    );
}