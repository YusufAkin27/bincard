package akin.city_card.feedback.repository;

import akin.city_card.feedback.model.Feedback;
import akin.city_card.feedback.model.FeedbackType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface FeedbackRepository extends JpaRepository<Feedback, Long> {

    @Query("SELECT f FROM Feedback f " +
            "WHERE (:type IS NULL OR f.type = :type) " +
            "AND (:source IS NULL OR f.source = :source) " +
            "AND f.submittedAt BETWEEN :startDateTime AND :endDateTime " +
            "ORDER BY f.submittedAt DESC")
    Page<Feedback> findFiltered(
            @Param("type") FeedbackType type,
            @Param("source") String source,
            @Param("startDateTime") LocalDateTime startDateTime,
            @Param("endDateTime") LocalDateTime endDateTime,
            Pageable pageable
    );

    // Geliştirilmiş filtreleme - anonim durumunu da içeren
    @Query("SELECT f FROM Feedback f " +
            "WHERE (:type IS NULL OR f.type = :type) " +
            "AND (:source IS NULL OR f.source = :source) " +
            "AND (:isAnonymous IS NULL OR f.isAnonymous = :isAnonymous) " +
            "AND f.submittedAt BETWEEN :startDateTime AND :endDateTime " +
            "ORDER BY f.submittedAt DESC")
    Page<Feedback> findFilteredWithAnonymous(
            @Param("type") FeedbackType type,
            @Param("source") String source,
            @Param("isAnonymous") Boolean isAnonymous,
            @Param("startDateTime") LocalDateTime startDateTime,
            @Param("endDateTime") LocalDateTime endDateTime,
            Pageable pageable
    );

    // Anonim feedback'leri getir
    @Query("SELECT f FROM Feedback f WHERE f.isAnonymous = true ORDER BY f.submittedAt DESC")
    Page<Feedback> findAnonymousFeedbacks(Pageable pageable);

    // Kayıtlı kullanıcı feedback'lerini getir
    @Query("SELECT f FROM Feedback f WHERE f.isAnonymous = false AND f.user IS NOT NULL ORDER BY f.submittedAt DESC")
    Page<Feedback> findUserFeedbacks(Pageable pageable);

    // Belirli bir kullanıcının feedback'lerini getir
    @Query("SELECT f FROM Feedback f WHERE f.user.id = :userId ORDER BY f.submittedAt DESC")
    Page<Feedback> findByUserId(@Param("userId") Long userId, Pageable pageable);

    // Kullanıcı numarası ile feedback'leri getir
    @Query("SELECT f FROM Feedback f WHERE f.user.userNumber = :userNumber ORDER BY f.submittedAt DESC")
    Page<Feedback> findByUserNumber(@Param("userNumber") String userNumber, Pageable pageable);

    // Feedback türüne göre istatistik
    @Query("SELECT f.type as type, COUNT(f) as count FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate " +
            "GROUP BY f.type " +
            "ORDER BY count DESC")
    List<Object[]> getFeedbackStatsByType(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // Kaynak türüne göre istatistik
    @Query("SELECT COALESCE(f.source, 'UNKNOWN') as source, COUNT(f) as count FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate " +
            "GROUP BY f.source " +
            "ORDER BY count DESC")
    List<Object[]> getFeedbackStatsBySource(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // Anonim vs Kayıtlı kullanıcı istatistikleri
    @Query("SELECT " +
            "SUM(CASE WHEN f.isAnonymous = true THEN 1 ELSE 0 END) as anonymousCount, " +
            "SUM(CASE WHEN f.isAnonymous = false THEN 1 ELSE 0 END) as userCount, " +
            "COUNT(f) as totalCount " +
            "FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate")
    Object[] getAnonymousVsUserStats(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // Aylık feedback sayısı
    @Query("SELECT YEAR(f.submittedAt) as year, MONTH(f.submittedAt) as month, COUNT(f) as count, " +
            "SUM(CASE WHEN f.isAnonymous = true THEN 1 ELSE 0 END) as anonymousCount, " +
            "SUM(CASE WHEN f.isAnonymous = false THEN 1 ELSE 0 END) as userCount " +
            "FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate " +
            "GROUP BY YEAR(f.submittedAt), MONTH(f.submittedAt) " +
            "ORDER BY year DESC, month DESC")
    List<Object[]> getMonthlyFeedbackStats(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // Günlük feedback sayısı
    @Query("SELECT DATE(f.submittedAt) as date, COUNT(f) as count, " +
            "SUM(CASE WHEN f.isAnonymous = true THEN 1 ELSE 0 END) as anonymousCount, " +
            "SUM(CASE WHEN f.isAnonymous = false THEN 1 ELSE 0 END) as userCount " +
            "FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate " +
            "GROUP BY DATE(f.submittedAt) " +
            "ORDER BY date DESC")
    List<Object[]> getDailyFeedbackStats(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // Haftalık feedback sayısı
    @Query("SELECT YEARWEEK(f.submittedAt) as yearWeek, COUNT(f) as count, " +
            "SUM(CASE WHEN f.isAnonymous = true THEN 1 ELSE 0 END) as anonymousCount, " +
            "SUM(CASE WHEN f.isAnonymous = false THEN 1 ELSE 0 END) as userCount " +
            "FROM Feedback f " +
            "WHERE f.submittedAt BETWEEN :startDate AND :endDate " +
            "GROUP BY YEARWEEK(f.submittedAt) " +
            "ORDER BY yearWeek DESC")
    List<Object[]> getWeeklyFeedbackStats(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    // En son feedback'ler
    @Query("SELECT f FROM Feedback f ORDER BY f.submittedAt DESC")
    List<Feedback> findLatestFeedbacks(Pageable pageable);

    // Contact email ile feedback'leri getir (anonim kullanıcılar için)
    @Query("SELECT f FROM Feedback f WHERE f.contactEmail = :email AND f.isAnonymous = true ORDER BY f.submittedAt DESC")
    List<Feedback> findByContactEmail(@Param("email") String email);

    // Belirli bir tarih sonrası feedback sayısı
    @Query("SELECT COUNT(f) FROM Feedback f WHERE f.submittedAt >= :date")
    long countFeedbacksAfterDate(@Param("date") LocalDateTime date);

    // Fotoğraflı feedback'ler
    @Query("SELECT f FROM Feedback f WHERE f.photoUrl IS NOT NULL ORDER BY f.submittedAt DESC")
    Page<Feedback> findFeedbacksWithPhotos(Pageable pageable);

    // Response gerekli feedback'ler (contact bilgisi olan)
    @Query("SELECT f FROM Feedback f WHERE " +
            "(f.isAnonymous = true AND f.contactEmail IS NOT NULL) OR " +
            "(f.isAnonymous = false AND f.user IS NOT NULL) " +
            "ORDER BY f.submittedAt DESC")
    Page<Feedback> findFeedbacksRequiringResponse(Pageable pageable);
}