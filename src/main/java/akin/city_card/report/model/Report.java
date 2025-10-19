package akin.city_card.report.model;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
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

    // Şikayeti üstlenen admin
    @ManyToOne
    @JoinColumn(name = "assigned_admin_id")
    private SecurityUser assignedAdmin;

    // Şikayet öncelik seviyesi
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private ReportPriority priority = ReportPriority.MEDIUM;

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
    @Builder.Default
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
    @Builder.Default
    private int unreadByUser = 0;

    // Okunmamış mesaj sayısı (admin için)
    @Column(nullable = false)
    @Builder.Default
    private int unreadByAdmin = 0;

    @Column(nullable = false)
    @Builder.Default
    private boolean deleted = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean archived = false;

    // Admin tarafından üstlene alındı mı?
    @Column(nullable = false)
    @Builder.Default
    private boolean isAssigned = false;

    // Üstlene alınma zamanı
    @Column(name = "assigned_at")
    private LocalDateTime assignedAt;

    // Çözüm süresi (dakika)
    @Column(name = "resolution_time_minutes")
    private Long resolutionTimeMinutes;

    // Çözüm tarihi
    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    // Admin notları (sadece adminler görebilir)
    @Column(name = "admin_notes", columnDefinition = "TEXT")
    private String adminNotes;

    // ===== MEMNUNIYET ALANLARI =====

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
    @Builder.Default
    private boolean isRated = false;

    @PrePersist
    public void onCreate() {
        this.lastMessageAt = LocalDateTime.now();
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

    // Şikayeti admin'e ata
    public void assignToAdmin(SecurityUser admin) {
        this.assignedAdmin = admin;
        this.isAssigned = true;
        this.assignedAt = LocalDateTime.now();
        if (this.status == ReportStatus.OPEN) {
            this.status = ReportStatus.IN_REVIEW;
        }
    }

    // Şikayet atamasını kaldır
    public void unassignFromAdmin() {
        this.assignedAdmin = null;
        this.isAssigned = false;
        this.assignedAt = null;
    }

    // Şikayeti çöz
    public void resolveReport() {
        this.status = ReportStatus.RESOLVED;
        this.resolvedAt = LocalDateTime.now();
        if (this.assignedAt != null) {
            this.resolutionTimeMinutes = java.time.Duration.between(this.assignedAt, this.resolvedAt).toMinutes();
        }
    }

    // ===== MEMNUNIYET METHODLARI =====

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

    // Admin notlarını güncelle
    public void updateAdminNotes(String notes) {
        this.adminNotes = notes;
    }
}