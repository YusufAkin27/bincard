package akin.city_card.buscard.core.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.LocalDate;

@Data
public class CreateSubscriptionRequest {
    @NotBlank(message = "Card UID is required")
    private String uid;
    
    @NotBlank(message = "Subscription type is required")
    private String type;

    private int loaded = 1;
    private LocalDate startDate;
    private LocalDate endDate;
    private int remainingUses = 30;
    private int remainingDays = 30;
}