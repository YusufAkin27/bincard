package akin.city_card.report.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "report_photos")
@Data
public class ReportPhoto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "report_id")
    private Report report;
}
