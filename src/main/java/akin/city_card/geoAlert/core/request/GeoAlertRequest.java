package akin.city_card.geoAlert.core.request;

import jakarta.validation.constraints.*;
import lombok.Data;


@Data
public class GeoAlertRequest {

    @NotNull(message = "Rota ID'si boş olamaz")
    private Long routeId;

    @NotNull(message = "Durak ID'si boş olamaz")
    private Long stationId;

    @NotBlank(message = "Uyarı adı boş olamaz")
    @Size(max = 100, message = "Uyarı adı en fazla 100 karakter olabilir")
    private String alertName;

    @Min(value = 1, message = "Bildirim süresi en az 1 dakika olmalıdır")
    @Max(value = 30, message = "Bildirim süresi en fazla 30 dakika olabilir")
    private int notifyBeforeMinutes = 5;

    @Min(value = 100, message = "Yarıçap en az 100 metre olmalıdır")
    @Max(value = 2000, message = "Yarıçap en fazla 2000 metre olabilir")
    private Double radiusMeters = 500.0;

    @Size(max = 500, message = "Notlar en fazla 500 karakter olabilir")
    private String notes;
}