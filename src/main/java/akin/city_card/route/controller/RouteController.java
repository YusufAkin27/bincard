package akin.city_card.route.controller;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.RouteSuggestionRequest;
import akin.city_card.route.core.response.*;
import akin.city_card.route.exceptions.RouteAlreadyFavoriteException;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.route.model.DirectionType;
import akin.city_card.route.service.abstracts.RouteService;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.exceptions.StationNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/route")
@RequiredArgsConstructor
public class RouteController {

    private final RouteService routeService;

    /**
     * İki yönlü rota oluşturma
     */
    @PostMapping("/create-bidirectional")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('ROUTE_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage createBidirectionalRoute(@AuthenticationPrincipal UserDetails userDetails,
                                                    @RequestBody CreateRouteRequest request)
            throws StationNotFoundException, UnauthorizedAreaException {
        return routeService.createBidirectionalRoute(userDetails.getUsername(), request);
    }

    /**
     * Rotayı silme
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('ROUTE_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage deleteRoute(@AuthenticationPrincipal UserDetails userDetails,
                                       @PathVariable Long id)
            throws UnauthorizedAreaException, RouteNotFoundException {
        return routeService.deleteRoute(userDetails.getUsername(), id);
    }

    /**
     * Belirli yöne durak ekleme
     */
    @PostMapping("/{routeId}/direction/{directionType}/add-station")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('ROUTE_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<RouteDTO> addStationToDirection(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long routeId,
            @PathVariable DirectionType directionType,
            @RequestParam Long afterStationId,
            @RequestParam Long newStationId)
            throws StationNotFoundException, RouteNotFoundException {
        return routeService.addStationToDirection(routeId, directionType, afterStationId,
                newStationId, userDetails.getUsername());
    }

    /**
     * Belirli yönden durak çıkarma
     */
    @DeleteMapping("/{routeId}/direction/{directionType}/remove-station")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('ROUTE_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<RouteDTO> removeStationFromDirection(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long routeId,
            @PathVariable DirectionType directionType,
            @RequestParam Long stationId)
            throws StationNotFoundException, RouteNotFoundException {
        return routeService.removeStationFromDirection(routeId, directionType, stationId,
                userDetails.getUsername());
    }

    /**
     * Tüm aktif rotaları listeleme
     */
    @GetMapping("/all")
    public DataResponseMessage<List<RouteNameDTO>> getAllRoutes() {
        return routeService.getAllRoutes();
    }

    /**
     * Rota detaylarını getirme
     */
    @GetMapping("/{id}")
    public DataResponseMessage<RouteDTO> getRouteById(@PathVariable Long id)
            throws RouteNotFoundException {
        return routeService.getRouteById(id);
    }

    /**
     * Rota yönlerini getirme
     */
    @GetMapping("/{id}/directions")
    public DataResponseMessage<List<RouteDirectionDTO>> getRouteDirections(@PathVariable Long id)
            throws RouteNotFoundException {
        return routeService.getRouteDirections(id);
    }

    /**
     * Belirli yöndeki durakları getirme
     */
    @GetMapping("/{routeId}/direction/{directionType}/stations")
    public DataResponseMessage<List<StationOrderDTO>> getStationsInDirection(
            @PathVariable Long routeId,
            @PathVariable DirectionType directionType)
            throws RouteNotFoundException {
        return routeService.getStationsInDirection(routeId, directionType);
    }

    /**
     * İsme göre rota arama
     */
    @GetMapping("/search")
    public DataResponseMessage<List<RouteNameDTO>> searchRoutesByName(@RequestParam String name) {
        return routeService.searchRoutesByName(name);
    }

    /**
     * Durağa göre rota arama ve sonraki otobüs bilgisi
     */
    @GetMapping("/search-by-station")
    public DataResponseMessage<List<RouteWithNextBusDTO>> searchRoutesByStationId(
            @RequestParam Long stationId) throws StationNotFoundException {
        return routeService.findRoutesWithNextBus(stationId);
    }

    /**
     * Favorilere ekleme
     */
    @PostMapping("/favorite")
    public ResponseMessage addFavorite(@AuthenticationPrincipal UserDetails userDetails,
                                       @RequestParam Long routeId)
            throws UserNotFoundException, RouteNotActiveException, RouteNotFoundException, RouteAlreadyFavoriteException {
        return routeService.addFavorite(userDetails.getUsername(), routeId);
    }

    /**
     * Favorilerden çıkarma
     */
    @DeleteMapping("/favorite")
    public ResponseMessage removeFavorite(@AuthenticationPrincipal UserDetails userDetails,
                                          @RequestParam Long routeId)
            throws UserNotFoundException, RouteNotActiveException, RouteNotFoundException {
        return routeService.removeFavorite(userDetails.getUsername(), routeId);
    }

    /**
     * Kullanıcının favori rotalarını getirme
     */
    @GetMapping("/favorites")
    public DataResponseMessage<List<RouteNameDTO>> favoriteRoutes(
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return routeService.favoriteRoutes(userDetails.getUsername());
    }

    /**
     * Rota önerisi
     */
    @PostMapping("/suggest")
    public DataResponseMessage<RouteSuggestionResponse> suggestRoute(
            @RequestBody RouteSuggestionRequest request) {
        return routeService.suggestRoute(request);
    }
}