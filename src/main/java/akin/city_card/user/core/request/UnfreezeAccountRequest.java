package akin.city_card.user.core.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UnfreezeAccountRequest {
    @NotBlank(message = "Telefon boş olamaz")
    private String telephone;

    @NotBlank(message = "Şifre boş olamaz")
    private String password;

    private String note;
}