package akin.city_card.buscard.core.request;

import akin.city_card.buscard.model.CardType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class CreateBusCardRequest {
    @NotBlank(message = "User number is required")
    private String userNumber;

    @NotBlank(message = "Full name is required")
    private String fullName;

    @NotNull(message = "Card type is required")
    private CardType type;

    private BigDecimal initialBalance;
}