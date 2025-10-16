package akin.city_card.contract.core.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RejectContractRequest {

    @NotBlank(message = "Reddetme sebebi belirtilmeli")
    @Size(max = 1000, message = "Reddetme sebebi en fazla 1000 karakter olabilir")
    private String rejectionReason;
}