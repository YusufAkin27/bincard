package akin.city_card.station.service.abstracts;

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
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Set;

public interface StationService {


    DataResponseMessage<StationDTO> createStation(UserDetails userDetails, CreateStationRequest request) throws AdminNotFoundException, UnauthorizedAreaException;

    DataResponseMessage<StationDTO> updateStation(String username, UpdateStationRequest request);

    DataResponseMessage<StationDTO> changeStationStatus(Long id, boolean active, String username);

    ResponseMessage deleteStation(Long id, String username);

    DataResponseMessage<PageDTO<StationDTO>> getAllStations(Double v1, Double v2, StationType type, int page, int size);

    DataResponseMessage<StationDetailsDTO> getStationById(Long id, DirectionType directionType);

    DataResponseMessage<PageDTO<StationDTO>> searchStationsByName(String name, int page, int size);

    DataResponseMessage<PageDTO<StationDTO>> searchNearbyStations(SearchStationRequest request, int page, int size);

    DataResponseMessage<List<StationDTO>> getFavorite(String username);

    ResponseMessage removeFavoriteStation(String username, Long stationId);

    ResponseMessage addFavoriteStation(String username, Long stationId) throws StationNotFoundException, StationNotActiveException;

    Set<String> getMatchingKeywords(String query);

    DataResponseMessage<List<PublicRouteDTO>> getRoutes(Long stationId) throws StationNotFoundException;

    DataResponseMessage<PageDTO<StationDTO>> NearbyStations(double latitude, double longitude, int page, int size);
}
