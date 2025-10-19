package akin.city_card.buscard.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;

import java.time.LocalDate;

@Embeddable
@Data
public class SubscriptionInfo {

    @Column(name = "subscription_type")
    private String type;
    private int loaded;
    private LocalDate startDate;
    private LocalDate endDate;
    private int remainingUses;
    private int remainingDays;
}
