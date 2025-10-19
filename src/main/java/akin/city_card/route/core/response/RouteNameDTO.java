// RouteNameDTO.java - Güncellenmiş
package akin.city_card.route.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RouteNameDTO {

    private Long id;
    private String name;
    private String code;
    private String routeType;
    private String color;
    private String startStationName;
    private String endStationName;
    private Integer estimatedDurationMinutes;
    private Double totalDistanceKm;
    private RouteScheduleDTO routeSchedule;
    private boolean hasOutgoingDirection;
    private boolean hasReturnDirection;
}
