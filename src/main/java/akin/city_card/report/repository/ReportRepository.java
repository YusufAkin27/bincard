package akin.city_card.report.repository;

import aj.org.objectweb.asm.commons.Remapper;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.user.model.User;
import org.hibernate.query.Page;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long>, JpaSpecificationExecutor<Report> {
    List<Report> findByUser(User user,Pageable pageable);

    List<Report> findAllByCategoryAndUser(ReportCategory category, User user);

    List<Report> findAllByCategory(ReportCategory category);
}


