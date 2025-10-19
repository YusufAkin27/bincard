package akin.city_card.contract.core.request;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class AcceptContractRequest {

    @NotNull(message = "Onay durumu belirtilmeli")
    private Boolean accepted = true;

    private String ipAddress;
    private String userAgent;
    private String contractVersion;
}