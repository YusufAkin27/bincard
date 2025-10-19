package akin.city_card.contract.core.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateContractRequest {

    @NotBlank(message = "Sözleşme başlığı boş olamaz")
    @Size(max = 200, message = "Başlık en fazla 200 karakter olabilir")
    private String title;

    @NotBlank(message = "Sözleşme içeriği boş olamaz")
    private String content;

    @NotBlank(message = "Versiyon bilgisi boş olamaz")
    @Size(max = 50, message = "Versiyon en fazla 50 karakter olabilir")
    private String version;

    private boolean mandatory = false;
    private boolean active = true;
}