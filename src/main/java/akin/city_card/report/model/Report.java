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

    // İlk şikayet mesajı (chat başlangıcı)
    @Column(nullable = false, columnDefinition = "TEXT")
    private String initialMessage;

    // Chat mesajları
    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("sentAt ASC")
    private List<ReportMessage> messages;

    // Raporun durumu
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReportStatus status = ReportStatus.OPEN;

    // Raporun oluşturulma zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    // Son mesaj zamanı (chat sıralaması için)
    private LocalDateTime lastMessageAt;

    // Son mesajı gönderen (USER/ADMIN)
    @Enumerated(EnumType.STRING)
    private MessageSender lastMessageSender;

    // Okunmamış mesaj sayısı (kullanıcı için)
    @Column(nullable = false)
    private int unreadByUser = 0;

    // Okunmamış mesaj sayısı (admin için)
    @Column(nullable = false)
    private int unreadByAdmin = 0;

    @Column(nullable = false)
    private boolean deleted = false;

    @Column(nullable = false)
    private boolean isActive = true;

    @Column(nullable = false)
    private boolean archived = false;

    // ===== YENİ EKLENEN ALANLAR =====

    // Kullanıcı memnuniyet puanı (1-5 arası)
    @Column(name = "satisfaction_rating")
    private Integer satisfactionRating;

    // Memnuniyet puanı verilme zamanı
    @Column(name = "satisfaction_rated_at")
    private LocalDateTime satisfactionRatedAt;

    // Memnuniyet yorumu (opsiyonel)
    @Column(name = "satisfaction_comment", length = 500)
    private String satisfactionComment;

    // Puanlama yapıldı mı kontrolü
    @Column(name = "is_rated", nullable = false)
    private boolean isRated = false;

    @PrePersist
    public void onCreate() {
        this.lastMessageAt = this.createdAt;
        this.lastMessageSender = MessageSender.USER;
    }

    // Son mesaj bilgilerini güncelle
    public void updateLastMessage(MessageSender sender) {
        this.lastMessageAt = LocalDateTime.now();
        this.lastMessageSender = sender;

        // Okunmamış sayaçlarını artır
        if (sender == MessageSender.ADMIN) {
            this.unreadByUser++;
        } else {
            this.unreadByAdmin++;
        }
    }

    // Okunmamış mesajları sıfırla
    public void markAsReadBy(MessageSender reader) {
        if (reader == MessageSender.USER) {
            this.unreadByUser = 0;
        } else {
            this.unreadByAdmin = 0;
        }
    }

    // ===== YENİ EKLENEN METHODLAR =====

    // Memnuniyet puanı verme
    public void setSatisfactionRating(Integer rating, String comment) {
        if (rating != null && rating >= 1 && rating <= 5) {
            this.satisfactionRating = rating;
            this.satisfactionComment = comment;
            this.satisfactionRatedAt = LocalDateTime.now();
            this.isRated = true;
        }
    }

    // Puanlama yapılabilir mi kontrol
    public boolean canBeRated() {
        return !this.isRated &&
                (this.status == ReportStatus.RESOLVED ||
                        this.status == ReportStatus.REJECTED ||
                        this.status == ReportStatus.CANCELLED);
    }
}