package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.UserFavoriteCard;
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
import java.util.ArrayList;
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

    @Column(name = "national_id", length = 11, unique = true)
    private String nationalId;

    @Column(name = "birth_date")
    private LocalDate birthDate;


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PasswordResetToken> resetTokens = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NewsLike> likedNews;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NewsViewHistory> viewedNews;


    @Column(name = "wallet_activated")
    private boolean walletActivated = false;


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<BusCard> busCards;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserFavoriteCard> favoriteCards;


    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_favorite_routes",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "route_id")
    )
    private List<Route> favoriteRoutes;

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

    private boolean allowNegativeBalance = false;

    @Column(nullable = false)
    private Double negativeBalanceLimit = 0.0;

    private boolean autoTopUpEnabled = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpConfig> autoTopUpConfigs;

    @Embedded
    private NotificationPreferences notificationPreferences;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Wallet wallet;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<VerificationCode> verificationCodes = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<GeoAlert> geoAlerts;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SearchHistory> searchHistory;
}
