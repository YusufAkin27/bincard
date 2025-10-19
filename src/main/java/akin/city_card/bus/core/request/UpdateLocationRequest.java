package akin.city_card.bus.core.request;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateLocationRequest {

    @NotNull(message = "Enlem bilgisi gereklidir")
    @DecimalMin(value = "-90.0", message = "Enlem -90 ile 90 arasında olmalıdır")
    @DecimalMax(value = "90.0", message = "Enlem -90 ile 90 arasında olmalıdır")
    private Double latitude;

    @NotNull(message = "Boylam bilgisi gereklidir")
    @DecimalMin(value = "-180.0", message = "Boylam -180 ile 180 arasında olmalıdır")
    @DecimalMax(value = "180.0", message = "Boylam -180 ile 180 arasında olmalıdır")
    private Double longitude;

    @DecimalMin(value = "0.0", message = "Hız negatif olamaz")
    @DecimalMax(value = "200.0", message = "Hız 200 km/s'yi geçemez")
    private Double speed; // km/saat

    @DecimalMin(value = "0.0", message = "GPS doğruluğu negatif olamaz")
    @DecimalMax(value = "1000.0", message = "GPS doğruluğu 1000 metreyi geçemez")
    private Double accuracy; // metre
}