package akin.city_card.bus.controller;

import akin.city_card.bus.core.request.*;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.bus.service.abstracts.BusService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/v1/api/bus")
@RequiredArgsConstructor
public class BusController {

    private final BusService busService;

    // --- GENEL ---

    @GetMapping
    public DataResponseMessage<List<BusDTO>> getAllBuses(@AuthenticationPrincipal UserDetails userDetails) {
        return busService.getAllBuses(userDetails.getUsername());
    }

    @GetMapping("/{busId}")
    public DataResponseMessage<BusDTO> getBusById(@PathVariable Long busId, @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getBusById(busId, userDetails.getUsername());
    }

    @GetMapping("/active")
    public DataResponseMessage<List<BusDTO>> getActiveBuses(@AuthenticationPrincipal UserDetails userDetails) {
        return busService.getActiveBuses(userDetails.getUsername());
    }

    // --- ADMIN ---

    @PostMapping("/create")
    public ResponseMessage createBus(@RequestBody CreateBusRequest request, @AuthenticationPrincipal UserDetails userDetails) {
        return busService.createBus(request, userDetails.getUsername());
    }

    @PutMapping("/update/{busId}")
    public ResponseMessage updateBus(@PathVariable Long busId, @RequestBody UpdateBusRequest request, @AuthenticationPrincipal UserDetails userDetails) {
        return busService.updateBus(busId, request, userDetails.getUsername());
    }

    @DeleteMapping("/delete/{busId}")
    public ResponseMessage deleteBus(@PathVariable Long busId, @AuthenticationPrincipal UserDetails userDetails) {
        return busService.deleteBus(busId, userDetails.getUsername());
    }

    @PutMapping("/{busId}/toggle-active")
    public ResponseMessage toggleActiveStatus(@PathVariable Long busId, @AuthenticationPrincipal UserDetails userDetails) {
        return busService.toggleBusActive(busId, userDetails.getUsername());
    }

    // --- ŞOFÖR TANIMLAMA / GÜNCELLEME ---

    @PutMapping("/{busId}/assign-driver")
    public ResponseMessage assignDriverToBus(@PathVariable Long busId,
                                             @RequestBody AssignDriverRequest request,
                                             @AuthenticationPrincipal UserDetails userDetails) {
        return busService.assignDriver(busId, request.getDriverId(), userDetails.getUsername());
    }

    // --- KONUM / TAKİP / GEÇMİŞ ---

    @GetMapping("/{busId}/location")
    public DataResponseMessage<BusLocationDTO> getCurrentBusLocation(@PathVariable Long busId,
                                                                     @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getCurrentLocation(busId, userDetails.getUsername());
    }

    @PostMapping("/{busId}/location")
    public ResponseMessage updateBusLocation(@PathVariable Long busId,
                                             @RequestBody UpdateLocationRequest request,
                                             @AuthenticationPrincipal UserDetails userDetails) {
        return busService.updateLocation(busId, request, userDetails.getUsername());
    }

    @GetMapping("/{busId}/location-history")
    public DataResponseMessage<List<BusLocationDTO>> getLocationHistory(
            @PathVariable Long busId,
            @RequestParam(required = false) LocalDate date,
            @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getLocationHistory(busId, date, userDetails.getUsername());
    }

    // --- YOLCULUK / ÜCRET / KARTLA BİNİŞ ---

    @PostMapping("/{busId}/ride")
    public ResponseMessage rideWithCard(@PathVariable Long busId,
                                        @RequestBody RideRequest request,
                                        @AuthenticationPrincipal UserDetails userDetails) {
        return busService.rideWithCard(busId, request.getCardId(), request.getCardType(), userDetails.getUsername());
    }

    @GetMapping("/{busId}/rides")
    public DataResponseMessage<List<BusRideDTO>> getBusRides(@PathVariable Long busId,
                                                             @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getBusRides(busId, userDetails.getUsername());
    }

    // --- ROTA / DURAKLAR / MESAFE ---

    @PutMapping("/{busId}/route")
    public ResponseMessage assignRouteToBus(@PathVariable Long busId,
                                            @RequestBody AssignRouteRequest request,
                                            @AuthenticationPrincipal UserDetails userDetails) {
        return busService.assignRoute(busId, request.getRouteId(), userDetails.getUsername());
    }

    @GetMapping("/{busId}/route/stations")
    public DataResponseMessage<List<StationDTO>> getRouteStations(@PathVariable Long busId,
                                                                  @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getRouteStations(busId, userDetails.getUsername());
    }

    @GetMapping("/{busId}/eta")
    public DataResponseMessage<Double> getEstimatedTimeToStation(@PathVariable Long busId,
                                                                 @RequestParam Long stationId,
                                                                 @AuthenticationPrincipal UserDetails userDetails) {
        return busService.getEstimatedArrivalTime(busId, stationId, userDetails.getUsername());
    }
}
