package akin.city_card.report.repository;

import aj.org.objectweb.asm.commons.Remapper;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;


import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long>, JpaSpecificationExecutor<Report> {
    List<Report> findByUser(User user, Pageable pageable);

    List<Report> findAllByCategoryAndUser(ReportCategory category, User user);

    List<Report> findAllByCategory(ReportCategory category);


    // New methods needed for the service implementation:
    Page<Report> findByUserAndDeletedFalse(User user, Pageable pageable);
    Page<Report> findByUserAndCategoryAndDeletedFalse(User user, ReportCategory category, Pageable pageable);
    List<Report> findAllByCategoryAndUserAndDeletedFalse(ReportCategory category, User user);
    Page<Report> findByCategory(ReportCategory category, Pageable pageable);

    // Statistics methods
    long countByStatus(ReportStatus status);
    long countByDeletedTrue();
    long countByArchivedTrue();

    // Additional filtering methods
    Page<Report> findByDeletedFalse(Pageable pageable);
    Page<Report> findByArchivedFalse(Pageable pageable);
    Page<Report> findByStatusAndDeletedFalse(ReportStatus status, Pageable pageable);
}


