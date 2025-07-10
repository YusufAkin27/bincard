package akin.city_card.report.repository;

import akin.city_card.admin.model.Admin;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportResponse;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReportResponseRepository extends JpaRepository<ReportResponse, Long> {
    List<ReportResponse> findByReportOrderByRespondedAtAsc(Report report);
    List<ReportResponse> findByUserOrderByRespondedAtDesc(User user);
    List<ReportResponse> findByAdminOrderByRespondedAtDesc(Admin admin);
    List<ReportResponse> findByParentOrderByRespondedAtAsc(ReportResponse parent);

    // For threaded responses
    List<ReportResponse> findByReportAndParentIsNullOrderByRespondedAtAsc(Report report);
    List<ReportResponse> findByParentIsNotNullOrderByRespondedAtAsc();
}
