// NextBusDTO.java - Güncellenmiş
package akin.city_card.route.core.response;

import akin.city_card.route.model.DirectionType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class NextBusDTO {
    private String plate;
    private Integer arrivalInMinutes;
    private DirectionType direction;
    private String directionName;
    private String currentLocation;
    private int occupancyRate;
    private String busStatus;

    private Integer remainingStops;        // Kalan durak sayısı
    private Integer currentSpeed;          // Mevcut hız (km/h)
    private String trafficStatus;          // Trafik durumu
    private Double distanceToStation;      // Durağa mesafe (km)
    private LocalDateTime lastUpdate;      // Son güncelleme zamanı
}