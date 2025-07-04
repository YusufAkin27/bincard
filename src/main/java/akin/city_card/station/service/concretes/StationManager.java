package akin.city_card.station.service.concretes;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.station.core.request.CreateStationRequest;
import akin.city_card.station.core.request.UpdateStationRequest;
import akin.city_card.station.service.abstracts.StationService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StationManager implements StationService {
    @Override
    public DataResponseMessage<List<StationDTO>> getAllStations(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<StationDTO> getStationById(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<List<StationDTO>> searchStationsByName(String username, String name) {
        return null;
    }

    @Override
    public DataResponseMessage<StationDTO> createStation(UserDetails userDetails, CreateStationRequest request) {
        return null;
    }

    @Override
    public DataResponseMessage<StationDTO> updateStation(String username, UpdateStationRequest request) {
        return null;
    }

    @Override
    public DataResponseMessage<StationDTO> changeStationStatus(Long id, boolean active, String username) {
        return null;
    }

    @Override
    public ResponseMessage deleteStation(Long id, String username) {
        return null;
    }
}
