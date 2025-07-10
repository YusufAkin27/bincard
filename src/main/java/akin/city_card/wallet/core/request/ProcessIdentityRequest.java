package akin.city_card.wallet.core.request;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class ProcessIdentityRequest {

    @NotNull(message = "Başvuru ID'si zorunludur.")
    private Long requestId;

    @NotNull(message = "Onay kararı zorunludur.")
    private boolean approved;

    private String adminNote;
}
