package akin.city_card.user.model;

import akin.city_card.location.model.Location;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "device_history")
public class DeviceHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser user;

    // Cihaz bilgileri
    private String fcmToken;
    private String deviceId;          // Unique device identifier
    private String deviceName;        // Örn: "iPhone 14 Pro"
    private String deviceModel;       // Örn: "iPhone15,2"
    private String deviceType;        // Mobile, Desktop, Tablet, Smart TV vs.
    private String operatingSystem;   // Örn: "iOS 17.1", "Android 14"
    private String appVersion;        // Uygulama versiyonu
    private String userAgent;

    // IP ve lokasyon bilgileri
    private String ipAddress;
    private String city;              // GeoIP şehir
    private String region;            // GeoIP bölge  
    private String country;           // GeoIP ülke
    private String timezone;          // GeoIP timezone
    private String org;               // GeoIP org bilgisi

    // Lokasyon referansı (opsiyonel)
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "location_id")
    private Location location;

    // Zaman bilgileri
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime firstSeenAt;

    @UpdateTimestamp
    private LocalDateTime lastSeenAt;

    private LocalDateTime lastActiveAt;

    // Durum bilgileri
    @Column(nullable = false)
    private Boolean isActive = true;

    @Column(nullable = false)
    private Boolean isTrusted = false;  // Güvenilir cihaz işareti

    @Column(nullable = false)
    private Boolean isBanned = false;   // Cihaz engellenmiş mi

    private String banReason;           // Engelleme sebebi
    private LocalDateTime bannedAt;     // Engellenme zamanı
    private String bannedBy;            // Kim tarafından engellendiği

    // İstatistik bilgileri
    @Column(nullable = false)
    private Long loginCount = 0L;       // Bu cihazdan kaç kez giriş yapıldı

    private LocalDateTime lastLoginAt;  // Son giriş zamanı

    // Browser/App özellikleri (web için)
    private String browserName;         // Chrome, Safari, Firefox vs.
    private String browserVersion;
    private String screenResolution;
    private String language;

    // Push notification için
    private Boolean pushNotificationsEnabled = false;

    // Güvenlik
    private Boolean requiresReauth = false;  // Yeniden kimlik doğrulama gerekiyor mu

    // Soft delete
    private Boolean isDeleted = false;
    private LocalDateTime deletedAt;
}
