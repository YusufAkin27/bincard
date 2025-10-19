// RouteDTO.java
package akin.city_card.route.core.response;

import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RouteDTO {

    @JsonView(Views.Admin.class)
    private Long id;

    @JsonView(Views.Public.class)
    private String name;

    @JsonView(Views.Public.class)
    private String code;

    @JsonView(Views.Public.class)
    private String description;

    @JsonView(Views.Public.class)
    private String routeType;

    @JsonView(Views.Public.class)
    private String color;

    @JsonView(Views.Admin.class)
    private LocalDateTime createdAt;

    @JsonView(Views.Admin.class)
    private LocalDateTime updatedAt;

    @JsonView(Views.SuperAdmin.class)
    private boolean isActive;

    @JsonView(Views.SuperAdmin.class)
    private boolean isDeleted;

    @JsonView(Views.User.class)
    private StationDTO startStation;

    @JsonView(Views.User.class)
    private StationDTO endStation;

    @JsonView(Views.User.class)
    private Integer estimatedDurationMinutes;

    @JsonView(Views.User.class)
    private Double totalDistanceKm;

    @JsonView(Views.User.class)
    private RouteScheduleDTO schedule;

    @JsonView(Views.User.class)
    private List<RouteDirectionDTO> directions;

    @JsonView(Views.Admin.class)
    private List<BusDTO> assignedBuses;
}