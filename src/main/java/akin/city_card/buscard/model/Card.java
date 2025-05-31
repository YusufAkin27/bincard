package akin.city_card.buscard.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Entity
public class Card {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String cardNumber;

    @Enumerated(EnumType.STRING)
    private CardType type;

    private LocalDate validUntil;
    private boolean active;

    private BigDecimal cardBalance = BigDecimal.ZERO;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "card", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Activity> activityHistory;


    public void checkAndUpdateValidity() {
        if (this.active && this.validUntil != null && LocalDate.now().isAfter(this.validUntil)) {
            this.type = CardType.TAM;
            this.active = true;
        }
    }


    public boolean hasSufficientBalance(BigDecimal amount) {
        return this.cardBalance.compareTo(amount) >= 0;
    }

    public boolean isSubscriptionCard() {
        return this.type == CardType.ABONMAN;
    }
}
