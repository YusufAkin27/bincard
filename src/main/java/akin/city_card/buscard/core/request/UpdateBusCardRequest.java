package akin.city_card.buscard.core.request;

import akin.city_card.buscard.model.CardStatus;
import lombok.Data;

import java.time.LocalDate;

@Data
public class UpdateBusCardRequest {
    private String fullName;
    private CardStatus status;
    private Boolean active;
    private LocalDate expiryDate;
}