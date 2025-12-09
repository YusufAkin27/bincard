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
public class CurrentStationInfoDTO {
    private StationDTO currentStation; // lastSeenStation
    private LocalDateTime currentStationTime;
    private StationDTO nextStation;
    private Integer estimatedArrivalMinutes; // Sonraki durağa tahmini varış süresi (dakika)
    private String routeName;
    private String directionName;
    private Double currentLatitude;
    private Double currentLongitude;
    private LocalDateTime lastLocationUpdate;
}

