package akin.city_card.bus.core.request;

import akin.city_card.bus.model.BusStatus;
import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class UpdateBusRequest {

    @Size(min = 2, max = 20, message = "Plaka numarası 2-20 karakter arasında olmalıdır")
    private String numberPlate;

    private Long routeId;

    private Long driverId;

    @DecimalMin(value = "0.0", inclusive = true, message = "Ücret sıfırdan küçük olamaz")
    @DecimalMax(value = "1000.0", message = "Ücret 1000 TL'den fazla olamaz")
    private Double baseFare;

    @Min(value = 10, message = "Kapasite en az 10 olmalıdır")
    @Max(value = 200, message = "Kapasite en fazla 200 olmalıdır")
    private Integer capacity;

    private Boolean active;

    private BusStatus status;

    private Long currentDirectionId; // Yön değişimi için

    private String notes; // Güncelleme notları
}