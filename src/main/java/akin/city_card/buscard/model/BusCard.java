package akin.city_card.buscard.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Entity
@Data
@Inheritance(strategy = InheritanceType.JOINED)
public class BusCard {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String cardNumber;

    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(name = "card_type")
    private CardType type;

    private BigDecimal balance;

    @Enumerated(EnumType.STRING)
    private CardStatus status;

    private boolean active;

    private LocalDate issueDate;
    private LocalDate expiryDate;

    private boolean lowBalanceNotified = false;

    // Yeni alanlar
    private BigDecimal lastTransactionAmount;

    private LocalDate lastTransactionDate;

    private boolean visaCompleted;

    @Embedded
    private SubscriptionInfo subscriptionInfo;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private SecurityUser user;

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserFavoriteCard> favoredByUsers;

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Activity> activities;
}
