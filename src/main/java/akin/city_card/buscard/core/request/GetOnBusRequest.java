package akin.city_card.buscard.core.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class GetOnBusRequest {
    @NotBlank(message = "Card UID is required")
    private String uid;
    
    @NotBlank(message = "Validator ID is required")
    private String validatorId;
}
