// RouteWithNextBusDTO.java - Güncellenmiş
package akin.city_card.route.core.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class RouteWithNextBusDTO {
    private Long id;
    private String name;
    private String code;
    private String routeType;
    private String startStationName;
    private String endStationName;
    private RouteScheduleDTO routeSchedule;
    private List<NextBusDTO> nextBuses; // Her yön için ayrı otobüs bilgisi
    private Integer totalActiveBuses;
}