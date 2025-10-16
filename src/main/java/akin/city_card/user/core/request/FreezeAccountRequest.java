package akin.city_card.user.core.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FreezeAccountRequest {
    @NotBlank(message = "Dondurma nedeni belirtilmelidir")
    @Size(max = 500, message = "Dondurma nedeni 500 karakteri geçemez")
    private String reason;

    @Min(value = 1, message = "Dondurma süresi en az 1 gün olmalıdır")
    @Max(value = 365, message = "Dondurma süresi en fazla 365 gün olabilir")
    private int freezeDurationDays;
}

