package akin.city_card.security.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class QRLoginRequestDTO {
    @NotNull(message = "bu alan boş olamaz")
    private String data;
    private String telephone;
    private String password;
}
