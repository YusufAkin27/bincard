package akin.city_card.report.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

@Entity
public class ReportResponseRating {
    @Id
    @GeneratedValue private Long id;

    @ManyToOne(optional = false)
    private User user;

    @ManyToOne(optional = false)
    private ReportResponse response;

    @Column(nullable = false)
    private int rating; // 1–5
}
