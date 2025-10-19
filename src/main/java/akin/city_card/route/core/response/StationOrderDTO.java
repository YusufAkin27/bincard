// StationOrderDTO.java - Yeni
package akin.city_card.route.core.response;

import akin.city_card.bus.core.response.StationDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class StationOrderDTO {
    private int order;
    private StationDTO station;
    private Integer estimatedTimeFromPrevious;
    private Double distanceFromPrevious;
    private boolean isActive;
}
