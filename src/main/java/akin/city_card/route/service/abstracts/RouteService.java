package akin.city_card.route.service.abstracts;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.UpdateRouteRequest;
import akin.city_card.route.core.response.RouteDTO;
import akin.city_card.route.model.Route;

import java.util.List;

public interface RouteService {
    DataResponseMessage<List<RouteDTO>> getAllRoutes(String username);

    DataResponseMessage<RouteDTO> getRouteById(String username, Long id);

    DataResponseMessage<List<RouteDTO>> searchRoutesByName(String name);

    DataResponseMessage<List<Route>> findRoutesByStationId(Long stationId);

    ResponseMessage createRoute(CreateRouteRequest request);

    DataResponseMessage<RouteDTO> updateRoute(String username, UpdateRouteRequest request);

    ResponseMessage deleteRoute(String username, Long id);

    DataResponseMessage<Route> addStationToRoute(Long routeId, Long stationId, String username);

    DataResponseMessage<Route> removeStationFromRoute(Long routeId, Long stationId, String username);
}
