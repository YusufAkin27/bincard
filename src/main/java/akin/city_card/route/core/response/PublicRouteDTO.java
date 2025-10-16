package akin.city_card.route.core.response;

import akin.city_card.bus.core.response.StationDTO;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PublicRouteDTO {
    private Long id;
    private String name;
    private StationDTO startStation;
    private StationDTO endStation;
}
