package akin.city_card.route.service.concretes;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.UpdateRouteRequest;
import akin.city_card.route.core.response.RouteDTO;
import akin.city_card.route.model.Route;
import akin.city_card.route.service.abstracts.RouteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RouteManager implements RouteService {
    @Override
    public DataResponseMessage<List<RouteDTO>> getAllRoutes(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<RouteDTO> getRouteById(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<List<RouteDTO>> searchRoutesByName(String name) {
        return null;
    }

    @Override
    public DataResponseMessage<List<Route>> findRoutesByStationId(Long stationId) {
        return null;
    }

    @Override
    public ResponseMessage createRoute(CreateRouteRequest request) {
        return null;
    }

    @Override
    public DataResponseMessage<RouteDTO> updateRoute(String username, UpdateRouteRequest request) {
        return null;
    }

    @Override
    public ResponseMessage deleteRoute(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<Route> addStationToRoute(Long routeId, Long stationId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<Route> removeStationFromRoute(Long routeId, Long stationId, String username) {
        return null;
    }
}
