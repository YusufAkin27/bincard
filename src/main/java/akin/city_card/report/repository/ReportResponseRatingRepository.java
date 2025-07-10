package akin.city_card.report.repository;

import akin.city_card.report.model.ReportResponse;
import akin.city_card.report.model.ReportResponseRating;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ReportResponseRatingRepository extends JpaRepository<ReportResponseRating,Long> {
    Optional<ReportResponseRating> findByUserAndResponse(User user, ReportResponse response);
    List<ReportResponseRating> findByUser(User user);
    List<ReportResponseRating> findByResponse(ReportResponse response);

    // Statistics
    @Query("SELECT AVG(r.rating) FROM ReportResponseRating r WHERE r.response = :response")
    Double findAverageRatingByResponse(@Param("response") ReportResponse response);

    @Query("SELECT COUNT(r) FROM ReportResponseRating r WHERE r.response = :response")
    long countByResponse(@Param("response") ReportResponse response);
}
