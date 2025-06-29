package akin.city_card.wallet.core.request;

import jakarta.validation.constraints.*;
import lombok.Data;

import java.time.LocalDate;

@Data
public class CreateWalletRequest {

    @NotBlank(message = "T.C. Kimlik numarası boş olamaz.")
    @Size(min = 11, max = 11, message = "T.C. Kimlik numarası 11 haneli olmalıdır.")
    private String nationalId;

    @NotNull(message = "Doğum tarihi zorunludur.")
    private LocalDate birthDate;


}
