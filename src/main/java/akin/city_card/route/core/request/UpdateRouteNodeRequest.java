package akin.city_card.route.core.request;

import lombok.Data;

@Data
public class UpdateRouteNodeRequest {
    private Long fromStationId;
    private Long toStationId;

}
