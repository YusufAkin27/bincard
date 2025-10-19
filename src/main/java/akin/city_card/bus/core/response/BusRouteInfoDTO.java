package akin.city_card.bus.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BusRouteInfoDTO {
    private Long routeId;
    private String routeName;
    private String routeCode;
    private String startStationName;
    private String endStationName;
    private Integer totalStations;
    private Double routeLength; // km
    private Integer estimatedDuration; // dakika
    private List<StationDTO> stations;
    private String currentDirection;
    private StationDTO nextStation;
    private Integer stopsRemaining;
}