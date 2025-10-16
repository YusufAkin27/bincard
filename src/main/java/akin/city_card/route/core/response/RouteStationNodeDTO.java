// RouteStationNodeDTO.java - Güncellenmiş
package akin.city_card.route.core.response;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RouteStationNodeDTO {

    @JsonView(Views.User.class)
    private Long id;

    @JsonView(Views.User.class)
    private StationDTO fromStation;

    @JsonView(Views.User.class)
    private StationDTO toStation;

    @JsonView(Views.User.class)
    private int sequenceOrder;

    @JsonView(Views.User.class)
    private Integer estimatedTravelTimeMinutes;

    @JsonView(Views.User.class)
    private Double distanceKm;

    @JsonView(Views.User.class)
    private boolean isActive;

    @JsonView(Views.Admin.class)
    private String notes;
}