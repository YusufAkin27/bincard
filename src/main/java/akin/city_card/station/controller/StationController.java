package akin.city_card.station.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.response.PublicRouteDTO;
import akin.city_card.route.model.DirectionType;
import akin.city_card.station.core.request.CreateStationRequest;
import akin.city_card.station.core.request.SearchStationRequest;
import akin.city_card.station.core.request.UpdateStationRequest;
import akin.city_card.station.core.response.StationDetailsDTO;
import akin.city_card.station.exceptions.StationNotActiveException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.StationType;
import akin.city_card.station.service.abstracts.StationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/api/station")
public class StationController {

    private final StationService stationService;

    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('STATION_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<StationDTO> createStation(@AuthenticationPrincipal UserDetails userDetails, @RequestBody CreateStationRequest request) throws AdminNotFoundException, UnauthorizedAreaException {
        return stationService.createStation(userDetails, request);
    }

    @PutMapping
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('STATION_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<StationDTO> updateStation(@RequestBody UpdateStationRequest request, @AuthenticationPrincipal UserDetails userDetails) {
        return stationService.updateStation(userDetails.getUsername(), request);
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('STATION_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<StationDTO> changeStationStatus(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id, @RequestParam boolean active) {
        return stationService.changeStationStatus(id, active, userDetails.getUsername());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('STATION_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage deleteStation(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        return stationService.deleteStation(id, userDetails.getUsername());
    }

    @GetMapping("/{id}")
    public DataResponseMessage<StationDetailsDTO> getStationById(
            @PathVariable Long id,
            @RequestParam(required = false) DirectionType directionType
    ) {
        return stationService.getStationById(id, directionType);
    }


    @GetMapping
    public DataResponseMessage<PageDTO<StationDTO>> getAllStations(
            @RequestParam(required = false) Double latitude,
            @RequestParam(required = false) Double longitude,
            @RequestParam(required = false) StationType type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return stationService.getAllStations(latitude, longitude, type, page, size);
    }


    @PostMapping("/add-favorite")
    public ResponseMessage addFavoriteStation(@AuthenticationPrincipal UserDetails userDetails, @RequestParam Long stationId) throws StationNotFoundException, StationNotActiveException {
        return stationService.addFavoriteStation(userDetails.getUsername(), stationId);
    }

    @DeleteMapping("/remove-favorite")
    public ResponseMessage removeFavoriteStation(@AuthenticationPrincipal UserDetails userDetails, @RequestParam Long stationId) {
        return stationService.removeFavoriteStation(userDetails.getUsername(), stationId);
    }

    @GetMapping("/favorite")
    public DataResponseMessage<List<StationDTO>> getFavoriteStations(@AuthenticationPrincipal UserDetails userDetails) {
        return stationService.getFavorite(userDetails.getUsername());
    }


    @GetMapping("/search")
    public DataResponseMessage<PageDTO<StationDTO>> searchStations(
            @RequestParam String name,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return stationService.searchStationsByName(name, page, size);
    }


    @PostMapping("/search/nearby")
    public DataResponseMessage<PageDTO<StationDTO>> searchNearbyStations(@RequestBody SearchStationRequest request,
                                                                         @RequestParam(defaultValue = "0") int page,
                                                                         @RequestParam(defaultValue = "10") int size) {
        return stationService.searchNearbyStations(request, page, size);
    }

    @GetMapping("/keywords")
    public Set<String> searchKeywords(@RequestParam String query) {
        return stationService.getMatchingKeywords(query);
    }

    @GetMapping("/routes")
    public DataResponseMessage<List<PublicRouteDTO>> getRoutes(@RequestParam Long stationId) throws StationNotFoundException, StationNotActiveException {
        return stationService.getRoutes(stationId);
    }

    @GetMapping("/nearby")
    public DataResponseMessage<PageDTO<StationDTO>> getNearbyStations(
            @RequestParam double latitude,
            @RequestParam double longitude,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return stationService.NearbyStations(latitude, longitude, page, size);
    }


}
