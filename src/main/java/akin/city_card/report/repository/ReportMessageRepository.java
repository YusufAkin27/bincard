package akin.city_card.report.repository;

import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportMessage;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ReportMessageRepository extends JpaRepository<ReportMessage, Long> {
    Page<ReportMessage> findByReportOrderBySentAtAsc(Report report, Pageable pageable);

    Page<ReportMessage> findByReportAndDeletedFalseOrderBySentAtAsc(Report report, Pageable pageable);

    List<ReportMessage> findTop5ByReportAndDeletedFalseOrderBySentAtDesc(Report report);

    Optional<ReportMessage> findTopByReportAndDeletedFalseOrderBySentAtDesc(Report report);

    long countByReportAndDeletedFalse(Report report);

    List<ReportMessage> findByReportAndReadByUserFalse(Report report);

    List<ReportMessage> findByReportAndReadByAdminFalse(Report report);

    @Query("SELECT COUNT(m) FROM ReportMessage m WHERE m.report = :report AND m.readByUser = false AND m.sender = 'ADMIN'")
    int countUnreadByUser(@Param("report") Report report);

    @Query("SELECT COUNT(m) FROM ReportMessage m WHERE m.report = :report AND m.readByAdmin = false AND m.sender = 'USER'")
    int countUnreadByAdmin(@Param("report") Report report);

    List<ReportMessage> findTop3ByReportAndDeletedFalseOrderBySentAtDesc(Report report);

    List<ReportMessage> findTop3ByReportOrderBySentAtDesc(Report report);
}
