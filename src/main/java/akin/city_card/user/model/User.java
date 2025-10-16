package akin.city_card.user.model;

import akin.city_card.autoTopUp.model.AutoTopUpConfig;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.UserFavoriteCard;
import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.news.model.NewsLike;
import akin.city_card.news.model.NewsViewHistory;
import akin.city_card.notification.model.Notification;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.route.model.Route;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.station.model.Station;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.wallet.model.Wallet;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Table(name = "users")
@PrimaryKeyJoinColumn(name = "id")
public class User extends SecurityUser {

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private UserIdentityInfo identityInfo;


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<GeoAlert> geoAlerts;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<PasswordResetToken> resetTokens = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<NewsLike> likedNews;


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<NewsViewHistory> viewedNews;

    @Column(name = "wallet_activated")
    private boolean walletActivated = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<UserFavoriteCard> favoriteCards;

    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_favorite_routes",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "route_id")
    )
    @JsonIgnore
    private List<Route> favoriteRoutes;

    @ElementCollection
    @CollectionTable(name = "user_card_aliases", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "alias")
    @JsonIgnore
    private Map<BusCard, String> cardNicknames;

    @ElementCollection
    @CollectionTable(name = "low_balance_alerts", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyJoinColumn(name = "card_id")
    @Column(name = "threshold")
    @JsonIgnore
    private Map<BusCard, Double> lowBalanceAlerts;

    private boolean allowNegativeBalance = false;

    @Column(nullable = false)
    private Double negativeBalanceLimit = 0.0;

    private boolean autoTopUpEnabled = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<AutoTopUpConfig> autoTopUpConfigs;

    @Embedded
    @JsonIgnore
    private NotificationPreferences notificationPreferences;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private Wallet wallet;

    @OneToMany
    @JoinTable(
            name = "user_favorite_stations",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "station_id")
    )
    private List<Station> favoriteStations = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<VerificationCode> verificationCodes = new ArrayList<>();


    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<SearchHistory> searchHistory;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Notification> notifications = new ArrayList<>();


}
