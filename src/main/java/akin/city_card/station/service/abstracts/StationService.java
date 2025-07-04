package akin.city_card.station.service.abstracts;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.station.core.request.CreateStationRequest;
import akin.city_card.station.core.request.UpdateStationRequest;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface StationService {
    DataResponseMessage<List<StationDTO>> getAllStations(String username);

    DataResponseMessage<StationDTO> getStationById(String username, Long id);

    DataResponseMessage<List<StationDTO>> searchStationsByName(String username, String name);

    DataResponseMessage<StationDTO> createStation(UserDetails userDetails, CreateStationRequest request);

    DataResponseMessage<StationDTO> updateStation(String username, UpdateStationRequest request);

    DataResponseMessage<StationDTO> changeStationStatus(Long id, boolean active, String username);

    ResponseMessage deleteStation(Long id, String username);
}
