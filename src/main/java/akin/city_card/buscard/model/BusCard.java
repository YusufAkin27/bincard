package akin.city_card.buscard.model;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "bus_card")
@Data
public class BusCard {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Kart numarası benzersiz olmalı
    @Column(name = "card_number", unique = true, nullable = false)
    private String cardNumber;

    @Column(name = "full_name")
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(name = "card_type", nullable = false)
    private CardType type;

    @Column(nullable = false)
    private BigDecimal balance = BigDecimal.ZERO;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CardStatus status = CardStatus.ACTIVE;

    @Column(nullable = false)
    private boolean active = true;

    @Column(name = "issue_date")
    private LocalDate issueDate;

    @Column(name = "expiry_date")
    private LocalDate expiryDate;

    @Column(name = "low_balance_notified")
    private boolean lowBalanceNotified = false;

    @Column(name = "last_transaction_amount")
    private BigDecimal lastTransactionAmount = BigDecimal.ZERO;

    @Column(name = "last_transaction_date")
    private LocalDate lastTransactionDate;

    @Column(name = "visa_completed")
    private boolean visaCompleted = false;

    @Embedded
    private SubscriptionInfo subscriptionInfo;

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<UserFavoriteCard> favoredByUsers = new ArrayList<>();

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<BusCardActivity> activities = new ArrayList<>();

    @Column(name = "tx_counter", nullable = false)
    private Integer txCounter = 0;
}
