package akin.city_card.bus.core.request;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class CreateBusRequest {

    @NotBlank(message = "Plaka numarası boş olamaz")
    @Size(min = 2, max = 20, message = "Plaka numarası 2-20 karakter arasında olmalıdır")
    private String numberPlate;

    private Long routeId;

    private Long driverId;

    @NotNull(message = "Ücret bilgisi gereklidir")
    @DecimalMin(value = "0.0", inclusive = true, message = "Ücret sıfırdan küçük olamaz")
    @DecimalMax(value = "1000.0", message = "Ücret 1000 TL'den fazla olamaz")
    private Double baseFare;

    @Min(value = 10, message = "Kapasite en az 10 olmalıdır")
    @Max(value = 200, message = "Kapasite en fazla 200 olmalıdır")
    private Integer capacity = 50; // Varsayılan kapasite

    private String notes; // Opsiyonel notlar
}