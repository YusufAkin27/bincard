package akin.city_card.bus.service.abstracts;

import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.request.UpdateLocationRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusRide;
import akin.city_card.buscard.model.CardType;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.util.List;

public interface BusService {

    DataResponseMessage<List<BusDTO>> getAllBuses(String username);

    DataResponseMessage<BusDTO> getBusById(Long busId, String username);

    DataResponseMessage<List<BusDTO>> getActiveBuses(String username);

    ResponseMessage createBus(CreateBusRequest request, String username);

    ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username);

    ResponseMessage deleteBus(Long busId, String username);

    ResponseMessage toggleBusActive(Long busId, String username);

    ResponseMessage assignDriver(Long busId, Long driverId, String username);

    DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username);

    ResponseMessage updateLocation(Long busId, UpdateLocationRequest request, String username);

    DataResponseMessage<List<BusLocationDTO>> getLocationHistory(Long busId, LocalDate date, String username);

    ResponseMessage rideWithCard(Long busId, Long cardId, CardType cardType, String username);

    DataResponseMessage<List<BusRideDTO>> getBusRides(Long busId, String username);

    ResponseMessage assignRoute(Long busId, Long routeId, String username);

    DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username);

    DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId, String username);
}
