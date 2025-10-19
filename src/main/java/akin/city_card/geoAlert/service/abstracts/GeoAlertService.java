package akin.city_card.geoAlert.service.abstracts;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.geoAlert.core.request.GeoAlertRequest;
import akin.city_card.geoAlert.core.response.GeoAlertDTO;
import akin.city_card.geoAlert.model.GeoAlertStatus;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotFoundStationException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.exceptions.StationNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface GeoAlertService {
    List<GeoAlertDTO> getGeoAlerts(String username) throws UserNotFoundException;

    ResponseMessage addGeoAlert(String username, GeoAlertRequest alertRequest) throws UserNotFoundException, RouteNotFoundException, StationNotFoundException, RouteNotFoundStationException;

    ResponseMessage deleteGeoAlert(String username, Long alertId) throws UserNotFoundException;

    int getActiveAlertCount(String username, Long routeId) throws UserNotFoundException;

    ResponseMessage reactivateGeoAlert(String username, Long alertId) throws UserNotFoundException;

    ResponseMessage cancelGeoAlert(String username, Long alertId) throws UserNotFoundException;

    ResponseMessage createGeoAlert(String username, GeoAlertRequest alertRequest) throws UserNotFoundException, RouteNotFoundException, StationNotFoundException, RouteNotFoundStationException;

    List<GeoAlertDTO> getGeoAlertHistory(String username) throws UserNotFoundException;

    List<GeoAlertDTO> getActiveGeoAlerts(String username) throws UserNotFoundException;

    long countGeoAlertsByStatus(String username, GeoAlertStatus status);

    ResponseMessage deleteGeoAlertAsAdmin(Long alertId, String username);

    List<GeoAlertDTO> getGeoAlertsByUsername(UserDetails userDetails, String username, GeoAlertStatus status);

    List<GeoAlertDTO> getAllGeoAlerts(String username, GeoAlertStatus status);
}
