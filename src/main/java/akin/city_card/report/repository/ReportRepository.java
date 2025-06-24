package akin.city_card.report.repository;

import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long> {
    List<Report> findByUser(User user);

    List<Report> findAllByCategoryAndUser(ReportCategory category, User user);

    List<Report> findAllByCategory(ReportCategory category);
}
