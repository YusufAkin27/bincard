package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
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

import java.time.LocalDateTime;
import java.util.Map;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Table(name = "users")
@PrimaryKeyJoinColumn(name = "id")
public class User extends SecurityUser {

    @Column(nullable = false, length = 50)
    private String name;

    @Column(nullable = false, length = 50)
    private String surname;

    private boolean active = true;
    private boolean phoneVerified = false;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<BusCard> busCards;

    @OneToOne
    private BusCard favoriteCard;

    @OneToOne
    private Route favoriteRoute;

    @ElementCollection
    @CollectionTable(name = "user_card_aliases", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "alias")
    private Map<BusCard, String> cardNicknames;

    @ElementCollection
    @CollectionTable(name = "low_balance_alerts", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "threshold")
    private Map<BusCard, Double> lowBalanceAlerts;

    // NEGATİF BAKİYE ÖZELLİĞİ
    private boolean allowNegativeBalance = false;

    // Başlangıç değeri -10, bu alanda tutulur
    @Column(nullable = false)
    private Double negativeBalanceLimit = -10.0;

    // OTOMATİK YÜKLEME
    private boolean autoTopUpEnabled = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpConfig> autoTopUpConfigs;

    @OneToMany(mappedBy = "autoTopUpConfig", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpLog> autoTopUpLogs;

    @Embedded
    private NotificationPreferences notificationPreferences;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Wallet wallet;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<VerificationCode> verificationCodes;
}
