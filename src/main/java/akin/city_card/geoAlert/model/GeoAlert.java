package akin.city_card.geoAlert.model;

import akin.city_card.route.model.Route;
import akin.city_card.station.model.Station;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "geo_alert", indexes = {
        @Index(name = "idx_user_status", columnList = "user_id, status"),
        @Index(name = "idx_route_station_status", columnList = "route_id, station_id, status"),
        @Index(name = "idx_status_created", columnList = "status, created_at"),
        @Index(name = "idx_user_created", columnList = "user_id, created_at")
})
public class GeoAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "route_id", nullable = false)
    private Route route;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "station_id", nullable = false)
    private Station station;

    @Column(length = 100, nullable = false)
    private String alertName;

    @Builder.Default
    @Min(value = 100, message = "Yarıçap en az 100 metre olmalıdır")
    @Max(value = 2000, message = "Yarıçap en fazla 2000 metre olabilir")
    @Column(nullable = false)
    private Double radiusMeters = 500.0; // Varsayılan 500m

    @Builder.Default
    @Column(nullable = false)
    private int notifyBeforeMinutes = 5; // Varsayılan 5 dakika

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private GeoAlertStatus status = GeoAlertStatus.ACTIVE;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    private LocalDateTime notifiedAt;

    private LocalDateTime cancelledAt;

    @Column(length = 500)
    private String notes; // Kullanıcının notları

    // Uyarı tetiklendiğinde hangi araç için tetiklendiği
    @Column(length = 20)
    private String triggeredByBusPlate;

    // Uyarı performans metrikleri
    private Integer actualNotificationMinutes; // Gerçekte kaç dakika öncesinde bildirim gönderildi

    // Bildirim gönderme durumu takibi
    @Builder.Default
    @Column(nullable = false)
    private boolean pushNotificationSent = false;

    @Builder.Default
    @Column(nullable = false)
    private boolean smsNotificationSent = false;

    @Builder.Default
    @Column(nullable = false)
    private boolean emailNotificationSent = false;

    // Son kontrol zamanı (performans optimizasyonu için)
    private LocalDateTime lastCheckedAt;

    // Kaç kez kontrol edildi
    @Builder.Default
    @Column(nullable = false)
    private int checkCount = 0;

    // Uyarı önceliği (gelecekte kullanım için)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private GeoAlertPriority priority = GeoAlertPriority.NORMAL;

    // Tekrarlanan uyarı mı? (gelecekte kullanım için)
    @Builder.Default
    @Column(nullable = false)
    private boolean isRecurring = false;

    // Haftanın hangi günleri aktif (tekrarlanan uyarılar için)
    @Column(length = 20)
    private String activeDaysOfWeek; // "1,2,3,4,5" gibi format

    // Hangi saatler arası aktif (tekrarlanan uyarılar için)
    private LocalDateTime activeTimeStart;
    private LocalDateTime activeTimeEnd;

    /**
     * Uyarının aktif olup olmadığını kontrol eder
     */
    public boolean isActive() {
        return status == GeoAlertStatus.ACTIVE;
    }

    /**
     * Uyarının tamamlanmış olup olmadığını kontrol eder
     */
    public boolean isCompleted() {
        return status == GeoAlertStatus.COMPLETED;
    }

    /**
     * Uyarının iptal edilmiş olup olmadığını kontrol eder
     */
    public boolean isCancelled() {
        return status == GeoAlertStatus.CANCELLED;
    }

    /**
     * Uyarının süresi dolmuş mu kontrol eder
     */
    public boolean isExpired() {
        return status == GeoAlertStatus.EXPIRED;
    }

    /**
     * Uyarının tekrar kontrol edilmeye uygun olup olmadığını kontrol eder
     */
    public boolean shouldCheck() {
        if (!isActive()) {
            return false;
        }

        // Son kontrol zamanından beri en az 10 saniye geçmiş mi?
        if (lastCheckedAt != null) {
            return lastCheckedAt.isBefore(LocalDateTime.now().minusSeconds(10));
        }

        return true;
    }

    /**
     * Son kontrol zamanını günceller
     */
    public void updateLastChecked() {
        this.lastCheckedAt = LocalDateTime.now();
        this.checkCount++;
    }

    /**
     * Bildirim gönderildi olarak işaretle
     */
    public void markNotificationSent(String notificationType) {
        switch (notificationType.toLowerCase()) {
            case "push":
                this.pushNotificationSent = true;
                break;
            case "sms":
                this.smsNotificationSent = true;
                break;
            case "email":
                this.emailNotificationSent = true;
                break;
        }
    }

    /**
     * Tüm bildirimlerin gönderilip gönderilmediğini kontrol et
     */
    public boolean allNotificationsSent() {
        if (user.getNotificationPreferences() == null) {
            return pushNotificationSent; // Varsayılan olarak sadece push
        }

        boolean allSent = true;

        if (user.getNotificationPreferences().isPushEnabled()) {
            allSent &= pushNotificationSent;
        }

        if (user.getNotificationPreferences().isSmsEnabled()) {
            allSent &= smsNotificationSent;
        }

        if (user.getNotificationPreferences().isEmailEnabled()) {
            allSent &= emailNotificationSent;
        }

        return allSent;
    }
}