package akin.city_card.report.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "reports")
public class Report {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Raporu oluşturan kullanıcı
    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    // Rapor kategorisi
    @Enumerated(EnumType.STRING)
    @Column(length = 50, nullable = false)
    private ReportCategory category;

    // Kullanıcının mesajı
    @Column(nullable = false, columnDefinition = "TEXT")
    private String message;

    // Fotoğraflar
    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ReportPhoto> photos;

    // Yanıtlar (çoklu yanıt desteği)
    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ReportResponse> responses;

    // Raporun durumu
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReportStatus status = ReportStatus.OPEN;

    // Raporun oluşturulma zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    // Son güncelleme zamanı (manuel kontrol gerekebilir)
    private LocalDateTime updatedAt;

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
