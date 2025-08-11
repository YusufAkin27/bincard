package akin.city_card.report.repository;

import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;


import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long>, JpaSpecificationExecutor<Report> {
    Page<Report> findByUserAndDeletedFalseAndIsActiveTrueOrderByLastMessageAtDesc(User user, Pageable pageable);
    Page<Report> findByUserAndCategoryAndDeletedFalseAndIsActiveTrueOrderByLastMessageAtDesc(User user, ReportCategory category, Pageable pageable);
    Page<Report> findByUserAndStatusAndDeletedFalseAndIsActiveTrueOrderByLastMessageAtDesc(User user, ReportStatus status, Pageable pageable);
    Page<Report> findByUserAndCategoryAndStatusAndDeletedFalseAndIsActiveTrueOrderByLastMessageAtDesc(User user, ReportCategory category, ReportStatus status, Pageable pageable);

    // Admin chat queries
    Page<Report> findByDeletedFalseOrderByLastMessageAtDesc(Pageable pageable);
    Page<Report> findByCategoryAndDeletedFalseOrderByLastMessageAtDesc(ReportCategory category, Pageable pageable);
    Page<Report> findByStatusAndDeletedFalseOrderByLastMessageAtDesc(ReportStatus status, Pageable pageable);
    Page<Report> findByCategoryAndStatusAndDeletedFalseOrderByLastMessageAtDesc(ReportCategory category, ReportStatus status, Pageable pageable);

    // Unread count queries
    @Query("SELECT SUM(r.unreadByUser) FROM Report r WHERE r.user = :user AND r.deleted = false AND r.isActive = true")
    Integer getTotalUnreadByUser(@Param("user") User user);

    @Query("SELECT SUM(r.unreadByAdmin) FROM Report r WHERE r.deleted = false")
    Integer getTotalUnreadByAdmin();
    // Puanlanan şikayet sayısı
    long countByIsRatedTrue();

    // Puanlanabilir ama henüz puanlanmamış şikayet sayısı
    long countByStatusInAndIsRatedFalse(List<ReportStatus> statuses);

    // Belirli puan alan şikayet sayısı
    long countBySatisfactionRating(Integer rating);

    // Ortalama memnuniyet puanı
    @Query("SELECT AVG(r.satisfactionRating) FROM Report r WHERE r.isRated = true")
    Double getAverageSatisfactionRating();

    // Kategori bazlı ortalama memnuniyet puanı
    @Query("SELECT AVG(r.satisfactionRating) FROM Report r WHERE r.category = :category AND r.isRated = true")
    Double getAverageSatisfactionRatingByCategory(@Param("category") ReportCategory category);

    // En yüksek puanlı şikayetler
    @Query("SELECT r FROM Report r WHERE r.isRated = true ORDER BY r.satisfactionRating DESC")
    List<Report> findTopRatedReports();

    // En düşük puanlı şikayetler
    @Query("SELECT r FROM Report r WHERE r.isRated = true ORDER BY r.satisfactionRating ASC")
    List<Report> findLowestRatedReports();

    // Belirli tarih aralığındaki memnuniyet ortalaması
    @Query("SELECT AVG(r.satisfactionRating) FROM Report r WHERE r.satisfactionRatedAt BETWEEN :startDate AND :endDate")
    Double getAverageSatisfactionRatingBetweenDates(@Param("startDate") LocalDateTime startDate,
                                                    @Param("endDate") LocalDateTime endDate);

    // Aylık memnuniyet trendi
    @Query("SELECT YEAR(r.satisfactionRatedAt) as year, MONTH(r.satisfactionRatedAt) as month, AVG(r.satisfactionRating) as avgRating " +
            "FROM Report r WHERE r.isRated = true " +
            "GROUP BY YEAR(r.satisfactionRatedAt), MONTH(r.satisfactionRatedAt) " +
            "ORDER BY year DESC, month DESC")
    List<Object[]> getMonthlySatisfactionTrend();
    // Stats queries
    long countByStatus(ReportStatus status);
    long countByCategory(ReportCategory category);
    long countByDeletedTrue();
    long countByArchivedTrue();
    long countByIsActiveTrue();
    long countByCreatedAtAfter(LocalDateTime dateTime);

    // Search queries
    @Query("SELECT DISTINCT r FROM Report r LEFT JOIN r.messages m WHERE " +
            "(LOWER(r.initialMessage) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(m.message) LIKE LOWER(CONCAT('%', :keyword, '%'))) AND " +
            "r.deleted = false")
    Page<Report> findByKeywordInMessageOrInitialMessage(@Param("keyword") String keyword, Pageable pageable);
}


