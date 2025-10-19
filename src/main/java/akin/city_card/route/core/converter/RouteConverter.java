package akin.city_card.route.core.converter;

import akin.city_card.route.core.response.*;
import akin.city_card.route.model.*;

public interface RouteConverter {

    RouteDTO toRouteDTO(Route route);

    RouteNameDTO toRouteNameDTO(Route route);

    RouteScheduleDTO toRouteScheduleDTO(RouteSchedule schedule);

    RouteStationNodeDTO toRouteStationNodeDTO(RouteStationNode node);

    RouteDirectionDTO toRouteDirectionDTO(RouteDirection direction);

    String formatDuration(Integer minutes);

    String formatDistance(Double distanceKm);

    String directionTypeToString(DirectionType directionType);

    PublicRouteDTO toPublicRoute(Route route);

    String formatRouteCode(Route route);

}
