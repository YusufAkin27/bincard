package akin.city_card.report.service.abstracts;

import org.springframework.data.jpa.domain.Specification;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;

public class ReportSpecification {

    public static Specification<Report> hasCategory(ReportCategory category) {
        return (root, query, criteriaBuilder) ->
                category == null ? null : criteriaBuilder.equal(root.get("category"), category);
    }

    public static Specification<Report> hasStatus(ReportStatus status) {
        return (root, query, criteriaBuilder) ->
                status == null ? null : criteriaBuilder.equal(root.get("status"), status);
    }

    public static Specification<Report> containsKeyword(String keyword) {
        return (root, query, cb) -> {
            if (keyword == null || keyword.isBlank()) {
                return cb.conjunction();
            }
            String pattern = "%" + keyword.toLowerCase() + "%";

            return cb.or(
                    cb.like(cb.lower(root.get("message")), pattern), // mesaj içeriği
                    cb.like(cb.lower(root.get("status").as(String.class)), pattern), // durum (OPEN, CLOSED)
                    cb.like(cb.lower(root.get("category").as(String.class)), pattern), // kategori (TEKNIK, vs.)
                    cb.like(cb.lower(root.get("user").get("userNumber")), pattern) // kullanıcı adı
            );
        };
    }


}
