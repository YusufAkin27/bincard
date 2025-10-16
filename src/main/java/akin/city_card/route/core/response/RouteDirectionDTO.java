// RouteDirectionDTO.java
package akin.city_card.route.core.response;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.route.model.DirectionType;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RouteDirectionDTO {

    @JsonView(Views.User.class)
    private Long id;

    @JsonView(Views.User.class)
    private String name;

    @JsonView(Views.User.class)
    private DirectionType type;

    @JsonView(Views.User.class)
    private StationDTO startStation;

    @JsonView(Views.User.class)
    private StationDTO endStation;

    @JsonView(Views.User.class)
    private Integer estimatedDurationMinutes;

    @JsonView(Views.User.class)
    private Double totalDistanceKm;

    @JsonView(Views.User.class)
    private boolean isActive;

    @JsonView(Views.User.class)
    private List<RouteStationNodeDTO> stationNodes;

    @JsonView(Views.User.class)
    private int totalStationCount;
}