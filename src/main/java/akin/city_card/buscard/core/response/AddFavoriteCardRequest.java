package akin.city_card.buscard.core.response;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AddFavoriteCardRequest {
    @NotBlank(message = "Card number is required")
    private String cardNumber;

    private String nickname;
}