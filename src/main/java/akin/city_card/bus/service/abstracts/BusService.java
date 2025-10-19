package akin.city_card.bus.service.abstracts;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.core.request.BusStatusUpdateRequest;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.exceptions.*;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;

import java.time.LocalDate;
import java.util.List;

public interface BusService {

    DataResponseMessage<PageDTO<BusDTO>> getAllBuses(int page, int size)
            throws AdminNotFoundException, UnauthorizedAreaException;

    DataResponseMessage<PageDTO<BusDTO>> getBusesByStatus(String status, String username, int page, int size);

    DataResponseMessage<BusDTO> getBusById(Long busId, String username)
            throws AdminNotFoundException, BusNotFoundException, UnauthorizedAreaException;

    DataResponseMessage<PageDTO<BusDTO>> getActiveBuses(String username, int page, int size);

    ResponseMessage createBus(CreateBusRequest request, String username)
            throws AdminNotFoundException, DuplicateBusPlateException, RouteNotFoundException, DriverNotFoundException, DriverInactiveException, DriverAlreadyAssignedToBusException, BusAlreadyAssignedAnotherDriverException, RouteNotActiveException, UserNotFoundException;

    ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username)
            throws AdminNotFoundException, DuplicateBusPlateException, DriverNotFoundException,
            RouteNotFoundException, BusNotFoundException, UserNotFoundException, DriverAlreadyAssignedToBusException, RouteDirectionNotFoundException;

    ResponseMessage deleteBus(Long busId, String username)
            throws AdminNotFoundException, BusNotFoundException, UserNotFoundException, BusAlreadyIsDeletedException;

    ResponseMessage toggleBusActive(Long busId, String username)
            throws AdminNotFoundException, BusNotFoundException;

    ResponseMessage assignDriver(Long busId, Long driverId, String username)
            throws AdminNotFoundException, BusNotFoundException, DriverNotFoundException, DriverAlreadyAssignedException, DriverInactiveException;

    DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username) throws BusNotFoundException, AdminNotFoundException, BusLocationNotFoundException;

    ResponseMessage updateLocation(Long busId, UpdateLocationRequest request)
            throws UnauthorizedLocationUpdateException, BusNotFoundException;

    DataResponseMessage<PageDTO<BusLocationDTO>> getLocationHistory(Long busId, LocalDate date, String username, int page, int size)
            throws UnauthorizedAccessException, BusNotFoundException, AdminNotFoundException;

    ResponseMessage assignRoute(Long busId, Long routeId, String username);

    DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username);

    DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId);

    ResponseMessage switchDirection(Long busId, String username) throws BusNotFoundException;

    DataResponseMessage<Object> getBusStatistics(String username);

    DataResponseMessage<PageDTO<BusDTO>> searchByNumberPlate(String numberPlate, String username, int page, int size);

    DataResponseMessage<PageDTO<BusDTO>> getBusesByRoute(Long routeId, String username, int page, int size);

    DataResponseMessage<PageDTO<BusDTO>> getBusesByDriver(Long driverId, String username, int page, int size);

    ResponseMessage updateBusStatus(Long busId, BusStatusUpdateRequest request, String username)
            throws BusNotFoundException;

    ResponseMessage updatePassengerCount(Long busId, Integer count, String username)
            throws BusNotFoundException;

    ResponseMessage bulkActivate(List<Long> busIds, String username);

    ResponseMessage bulkDeactivate(List<Long> busIds, String username);
}