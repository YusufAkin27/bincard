package akin.city_card.bus.core.request;

import akin.city_card.bus.model.BusStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class BusStatusUpdateRequest {

    @NotNull(message = "Durum bilgisi gereklidir")
    private BusStatus status;

    private String reason; // Durum değişim sebebi
    private Integer estimatedDurationMinutes; // Tahmini süre (mola, bakım vb. için)
}