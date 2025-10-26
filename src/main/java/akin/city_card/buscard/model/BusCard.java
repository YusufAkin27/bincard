package akin.city_card.buscard.model;

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

    @Column(unique = true, nullable = false)
    private String cardNumber;//32109381204

    private String fullName;// Yusuf akin olmayabilir de

    @Enumerated(EnumType.STRING)
    @Column(name = "card_type")
    private CardType type;

    private BigDecimal balance;

    @Enumerated(EnumType.STRING)
    private CardStatus status;

    private boolean active;

    private LocalDate issueDate;// verilme tarihi
    private LocalDate expiryDate;// son kullanma tarihi

    private boolean lowBalanceNotified = false;

    // Yeni alanlar
    private BigDecimal lastTransactionAmount;// en son yapılan işlem tutarı

    private LocalDate lastTransactionDate;// en son yapılan işlem zamanı

    private boolean visaCompleted;// vizesi var mı

    @Embedded
    private SubscriptionInfo subscriptionInfo;// abonman kart için

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserFavoriteCard> favoredByUsers;

    @OneToMany(mappedBy = "busCard", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<BusCardActivity> activities;

    @Column(name = "tx_counter")
    private Integer txCounter = 0;

}
