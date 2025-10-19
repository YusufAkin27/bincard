package akin.city_card.route.core.request;

import akin.city_card.route.model.TimeSlot;
import lombok.Data;

import java.util.List;

@Data
public class UpdateRouteRequest {
    private Long routeId;
    private String routeName;
    private Long startStationId;
    private Long endStationId;
    private List<TimeSlot> weekdayHours;
    private List<TimeSlot> weekendHours;
    private List<UpdateRouteNodeRequest> routeNodes;
}
