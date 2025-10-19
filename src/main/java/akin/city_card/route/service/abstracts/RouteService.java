package akin.city_card.route.service.abstracts;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.bus.model.Bus;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.RouteSuggestionRequest;
import akin.city_card.route.core.response.*;
import akin.city_card.route.exceptions.RouteAlreadyFavoriteException;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.route.model.DirectionType;
import akin.city_card.route.model.Route;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.Station;

import java.util.List;

public interface RouteService {

    /**
     * İsme göre rota arama
     */
    DataResponseMessage<List<RouteNameDTO>> searchRoutesByName(String name);

    /**
     * Yeni bidirectional rota oluşturma
     */
    ResponseMessage createBidirectionalRoute(String username, CreateRouteRequest request)
            throws UnauthorizedAreaException, StationNotFoundException;

    /**
     * Rotayı silme (soft delete)
     */
    ResponseMessage deleteRoute(String username, Long id)
            throws UnauthorizedAreaException, RouteNotFoundException;

    /**
     * Rota detaylarını getirme
     */
    DataResponseMessage<RouteDTO> getRouteById(Long id) throws RouteNotFoundException;

    /**
     * Tüm aktif rotaları listeleme
     */
    DataResponseMessage<List<RouteNameDTO>> getAllRoutes();

    /**
     * Belirli yöne durak ekleme
     */
    DataResponseMessage<RouteDTO> addStationToDirection(
            Long routeId,
            DirectionType directionType,
            Long afterStationId,
            Long newStationId,
            String username) throws StationNotFoundException, RouteNotFoundException;

    /**
     * Belirli yönden durak çıkarma
     */
    DataResponseMessage<RouteDTO> removeStationFromDirection(
            Long routeId,
            DirectionType directionType,
            Long stationId,
            String username) throws RouteNotFoundException, StationNotFoundException;

    /**
     * Favorilere ekleme
     */
    ResponseMessage addFavorite(String username, Long routeId)
            throws RouteNotActiveException, UserNotFoundException, RouteNotFoundException, RouteAlreadyFavoriteException;

    /**
     * Favorilerden çıkarma
     */
    ResponseMessage removeFavorite(String username, Long routeId)
            throws RouteNotFoundException, UserNotFoundException, RouteNotActiveException;

    /**
     * Kullanıcının favori rotalarını getirme
     */
    DataResponseMessage<List<RouteNameDTO>> favoriteRoutes(String username) throws UserNotFoundException;

    /**
     * Rota önerisi
     */
    DataResponseMessage<RouteSuggestionResponse> suggestRoute(RouteSuggestionRequest request);

    /**
     * Duraktan geçen rotalar ve sonraki otobüs bilgisi
     */
    DataResponseMessage<List<RouteWithNextBusDTO>> findRoutesWithNextBus(Long stationId)
            throws StationNotFoundException;

    /**
     * Rota yönlerini getirme
     */
    DataResponseMessage<List<RouteDirectionDTO>> getRouteDirections(Long routeId)
            throws RouteNotFoundException;

    /**
     * Belirli yöndeki durakları getirme
     */
    DataResponseMessage<List<StationOrderDTO>> getStationsInDirection(Long routeId, DirectionType directionType)
            throws RouteNotFoundException;

    List<Route> findRoutesByStationId(Long id);

    List<Bus> findActiveBusesForRoute(Route route);

    Bus findNearestBusToStation(List<Bus> directionBuses, Station station);
}