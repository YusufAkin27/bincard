package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.news.model.NewsLike;
import akin.city_card.news.model.NewsViewHistory;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.route.model.Route;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.wallet.model.Wallet;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Table(name = "users")
@PrimaryKeyJoinColumn(name = "id") // SecurityUser sınıfındaki ID ile join yapılır
public class User extends SecurityUser {

    // Kullanıcının adı
    @Column(nullable = false, length = 50)
    private String name;

    // Kullanıcının soyadı
    @Column(nullable = false, length = 50)
    private String surname;

    // Kullanıcı aktif mi? (soft delete için kullanılabilir)
    private boolean active = true;
    private boolean deleted = false;

    // Telefon doğrulandı mı?x
    private boolean phoneVerified = false;

    // Telefon doğrulandı mı?
    @Column(name = "email_verified")
    private boolean emailVerified = false;

    private String profilePicture="https://w7.pngwing.com/pngs/177/551/png-transparent-user-interface-design-computer-icons-default-stephen-salazar-graphy-user-interface-design-computer-wallpaper-sphere-thumbnail.png";

    private String email;


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NewsLike> likedNews;//beğendiği haberler

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NewsViewHistory> viewedNews;


    // Kimlik numarası (isteğe bağlı, sadece cüzdan aktifleştirildiğinde doldurulur)
    @Column(name = "national_id", length = 11, unique = true)
    private String nationalId;//kimlik numarası

    // Doğum tarihi (isteğe bağlı, sadece cüzdan aktifleştirildiğinde doldurulur)
    @Column(name = "birth_date")
    private LocalDate birthDate;

    // Cüzdan bilgileri aktif mi? (bu flag üzerinden kontrol edilir)
    @Column(name = "wallet_activated")
    private boolean walletActivated = false;

    // Kullanıcı oluşturulma zamanı (otomatik atanır)
    @CreationTimestamp
    private LocalDateTime createdAt;

    // Kullanıcı bilgileri son güncellenme zamanı
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    // Kullanıcının sahip olduğu otobüs kartları
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<BusCard> busCards;

    // Kullanıcının favori kartı
    @OneToOne
    private BusCard favoriteCard;

    // Kullanıcının favori güzergahı
    @OneToOne
    private Route favoriteRoute;

    // Son bilinen enlem (kullanıcının konum takibi için)
    @Column(name = "last_known_lat")
    private Double lastKnownLatitude;

    // Son bilinen boylam
    @Column(name = "last_known_lng")
    private Double lastKnownLongitude;

    // Konumun son güncellenme zamanı
    @Column(name = "last_location_updated_at")
    private LocalDateTime lastLocationUpdatedAt;

    // Kullanıcının sisteme son giriş yaptığı zaman
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    // Kullanıcının sisteme giriş yaptığı IP adresi
    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    // Kullanıcının giriş yaptığı cihaz adı veya modeli
    @Column(name = "last_login_device")
    private String lastLoginDevice;

    // Kullanıcının giriş yaptığı platform (örnek: Android, iOS, Web)
    @Column(name = "last_login_platform")
    private String lastLoginPlatform;

    // Kullanıcının giriş yaptığı uygulama versiyonu
    @Column(name = "last_login_app_version")
    private String lastLoginAppVersion;

    // Kullanıcının otobüs kartlarına verdiği takma adlar
    @ElementCollection
    @CollectionTable(name = "user_card_aliases", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "alias")
    private Map<BusCard, String> cardNicknames;

    // Her kart için belirlenen düşük bakiye uyarı eşiği
    @ElementCollection
    @CollectionTable(name = "low_balance_alerts", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "threshold")
    private Map<BusCard, Double> lowBalanceAlerts;

    // Kullanıcı negatif bakiyeye izin veriyor mu?
    private boolean allowNegativeBalance = false;

    @Column(nullable = false)
    private Double negativeBalanceLimit = 0.0;

    // Otomatik bakiye yükleme aktif mi?
    private boolean autoTopUpEnabled = false;

    // Kullanıcının otomatik yükleme yapılandırmaları
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpConfig> autoTopUpConfigs;


    // Bildirim tercihleri (email, push, SMS gibi)
    @Embedded
    private NotificationPreferences notificationPreferences;

    // Kullanıcının dijital cüzdanı (bakiye, işlemler vs.)
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Wallet wallet;

    // Kullanıcının doğrulama kod geçmişi (telefon doğrulama vs.)
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<VerificationCode> verificationCodes;

    // Kullanıcının konum bazlı bildirim ayarları
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<GeoAlert> geoAlerts;

    // Kullanıcının yaptığı geçmiş aramalar
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SearchHistory> searchHistory;




}
