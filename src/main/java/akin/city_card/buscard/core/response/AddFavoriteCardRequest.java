package akin.city_card.buscard.core.response;

import akin.city_card.buscard.model.CardType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class AddFavoriteCardRequest {
    @NotBlank(message = "Card number is required")
    private String cardNumber;
    
    private String nickname;
}