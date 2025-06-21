package akin.city_card.report.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "reports")
public class Report {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Raporu oluşturan kullanıcı
    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    // Kategori enum olabilir
    @Enumerated(EnumType.STRING)
    @Column(length = 50, nullable = false)
    private ReportCategory category;

    // Kullanıcının mesajı
    @Column(nullable = false, columnDefinition = "TEXT")
    private String message;

    // Fotoğraflar (isteğe bağlı, birden fazla olabilir)
    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ReportPhoto> photos;

    // Raporun oluşturulma zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    // Yanıt/inceleme durumu
    private boolean resolved = false;

    // (Opsiyonel) admin notu veya cevabı
    @Column(length = 1000)
    private String adminNote;
}
