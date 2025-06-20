package akin.city_card.buscard.model;

import akin.city_card.card_visa.model.CardVisa;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.Data;
import akin.city_card.card_visa.model.VisaStatus; // bu gerekli!


import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Entity
@Data
public class BusCard {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String cardNumber;

    @Enumerated(EnumType.STRING)
    private CardType type;

    private LocalDate validUntil;
    private boolean active;
    @Enumerated(EnumType.STRING)
    private CardStatus status;


    private BigDecimal cardBalance = BigDecimal.ZERO;
    private String cardAliasName;
    private LocalDate issuedDate;
    private String cardPhotoUrl;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "card", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Activity> activityHistory;

    @OneToMany(mappedBy = "card", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<CardVisa> visaHistory;


    public boolean isVisaValid() {
        return getActiveVisa() != null;
    }

    public CardVisa getActiveVisa() {
        LocalDate today = LocalDate.now();
        return visaHistory.stream()
                .filter(v -> v.getStatus() == VisaStatus.VALID
                        && !today.isBefore(v.getVisaStartDate())
                        && !today.isAfter(v.getVisaEndDate()))
                .findFirst()
                .orElse(null);
    }


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
