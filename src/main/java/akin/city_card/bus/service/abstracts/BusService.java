package akin.city_card.bus.service.abstracts;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.exceptions.*;
import akin.city_card.buscard.model.CardType;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;

import java.time.LocalDate;
import java.util.List;

public interface BusService {

    DataResponseMessage<List<BusDTO>> getAllBuses(String username) throws AdminNotFoundException;

    DataResponseMessage<BusDTO> getBusById(Long busId, String username) throws AdminNotFoundException, BusNotFoundException;

    DataResponseMessage<List<BusDTO>> getActiveBuses(String username);

    ResponseMessage createBus(CreateBusRequest request, String username) throws AdminNotFoundException, DuplicateBusPlateException, RouteNotFoundException, DriverNotFoundException;

    ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username) throws AdminNotFoundException, DuplicateBusPlateException, DriverNotFoundException, RouteNotFoundException, BusNotFoundException;

    ResponseMessage deleteBus(Long busId, String username) throws AdminNotFoundException, BusNotFoundException;

    ResponseMessage toggleBusActive(Long busId, String username) throws AdminNotFoundException, BusNotFoundException;

    ResponseMessage assignDriver(Long busId, Long driverId, String username) throws AdminNotFoundException, BusNotFoundException, DriverNotFoundException, DriverAlreadyAssignedException;

    DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username) throws UserNotFoundException, BusNotFoundException;

    ResponseMessage updateLocation(Long busId, UpdateLocationRequest request) throws UnauthorizedLocationUpdateException, BusNotFoundException;

    DataResponseMessage<List<BusLocationDTO>> getLocationHistory(Long busId, LocalDate date, String username) throws UnauthorizedAccessException, BusNotFoundException;

    ResponseMessage rideWithCard(Long busId, Long cardId, CardType cardType, String username) throws BusNotFoundException, CardNotFoundException, UnauthorizedCardUsageException, InsufficientBalanceException;

    DataResponseMessage<List<BusRideDTO>> getBusRides(Long busId, String username);

    ResponseMessage assignRoute(Long busId, Long routeId, String username);

    DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username);

    DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId, String username);
}
