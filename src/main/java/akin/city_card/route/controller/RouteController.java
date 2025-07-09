package akin.city_card.route.controller;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.UpdateRouteRequest;
import akin.city_card.route.core.response.RouteDTO;
import akin.city_card.route.model.Route;
import akin.city_card.route.service.abstracts.RouteService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/route")
@RequiredArgsConstructor
public class RouteController {

    private final RouteService routeService;

    //apiler boş

    @GetMapping("/getAllRoutes")
    public DataResponseMessage<List<RouteDTO>> getAllRoutes(@AuthenticationPrincipal UserDetails userDetails) {
        return routeService.getAllRoutes(userDetails.getUsername());
    }

    @GetMapping("/{id}")
    public DataResponseMessage<RouteDTO> getRouteById(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        return routeService.getRouteById(userDetails.getUsername(), id);
    }

    @GetMapping("/search-by-name")
    public DataResponseMessage<List<RouteDTO>> searchRoutesByName(@RequestParam String name) {
        return routeService.searchRoutesByName(name);
    }

    @GetMapping("/search-by-station")
    public DataResponseMessage<List<Route>> searchRoutesByStationId(@RequestParam Long stationId) {
        return routeService.findRoutesByStationId(stationId);
    }

    @PostMapping("/create-route")
    public ResponseMessage createRoute(@RequestBody CreateRouteRequest request) {
        return routeService.createRoute(request);
    }

    @PutMapping("/{id}")
    public DataResponseMessage<RouteDTO> updateRoute(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateRouteRequest request) {
        return routeService.updateRoute(userDetails.getUsername(), request);
    }

    @DeleteMapping("/{id}")
    public ResponseMessage deleteRoute(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        return routeService.deleteRoute(userDetails.getUsername(), id);
    }

    @PostMapping("/{routeId}/add-station")
    public DataResponseMessage<Route> addStationToRoute(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long routeId, @RequestParam Long stationId) {
        return routeService.addStationToRoute(routeId, stationId, userDetails.getUsername());
    }

    @DeleteMapping("/{routeId}/remove-station")
    public DataResponseMessage<Route> removeStationFromRoute(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long routeId, @RequestParam Long stationId) {
        return routeService.removeStationFromRoute(routeId, stationId, userDetails.getUsername());
    }

}
