package akin.city_card.station.controller;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.station.core.request.CreateStationRequest;
import akin.city_card.station.core.request.UpdateStationRequest;
import akin.city_card.station.service.abstracts.StationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/api/station")
public class StationController {

    private final StationService stationService;

    @GetMapping
    public DataResponseMessage<List<StationDTO>> getAllStations(@AuthenticationPrincipal UserDetails  userDetails) {
        return stationService.getAllStations(userDetails.getUsername());
    }

    @GetMapping("/{id}")
    public DataResponseMessage<StationDTO> getStationById(@AuthenticationPrincipal UserDetails userDetails,@PathVariable Long id) {
        return stationService.getStationById(userDetails.getUsername(),id);
    }

    @GetMapping("/search")
    public DataResponseMessage<List<StationDTO>> searchStations(@AuthenticationPrincipal UserDetails userDetails,@RequestParam String name) {
        return stationService.searchStationsByName(userDetails.getUsername(),name);
    }

    @PostMapping
    public DataResponseMessage<StationDTO> createStation(@AuthenticationPrincipal UserDetails userDetails,@RequestBody CreateStationRequest request) {
        return stationService.createStation(userDetails,request);
    }

    @PutMapping("/{id}")
    public DataResponseMessage<StationDTO> updateStation(@RequestBody UpdateStationRequest request, @AuthenticationPrincipal UserDetails userDetails) {
        return stationService.updateStation(userDetails.getUsername(), request);
    }

    @PatchMapping("/{id}/status")
    public DataResponseMessage<StationDTO> changeStationStatus(@AuthenticationPrincipal UserDetails userDetails,@PathVariable Long id, @RequestParam boolean active) {
        return stationService.changeStationStatus(id, active,userDetails.getUsername());
    }

    @DeleteMapping("/{id}")
    public ResponseMessage deleteStation(@AuthenticationPrincipal UserDetails userDetails,@PathVariable Long id) {
       return stationService.deleteStation(id,userDetails.getUsername());
    }
}
