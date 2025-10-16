package akin.city_card.bus.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BusLocationDTO {
    private double latitude;
    private double longitude;
    private LocalDateTime timestamp;
    private Double speed; // KM/saat
    private Double accuracy; // GPS doğruluğu (metre)
    private String closestStationName;
    private Double distanceToClosestStation; // metre
}