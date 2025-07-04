package akin.city_card.bus.service.concretes;

import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.request.UpdateLocationRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.service.abstracts.BusService;
import akin.city_card.buscard.model.CardType;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public class BusManager implements BusService {
    @Override
    public DataResponseMessage<List<BusDTO>> getAllBuses(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<BusDTO> getBusById(Long busId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<BusDTO>> getActiveBuses(String username) {
        return null;
    }

    @Override
    public ResponseMessage createBus(CreateBusRequest request, String username) {
        return null;
    }

    @Override
    public ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username) {
        return null;
    }

    @Override
    public ResponseMessage deleteBus(Long busId, String username) {
        return null;
    }

    @Override
    public ResponseMessage toggleBusActive(Long busId, String username) {
        return null;
    }

    @Override
    public ResponseMessage assignDriver(Long busId, Long driverId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username) {
        return null;
    }

    @Override
    public ResponseMessage updateLocation(Long busId, UpdateLocationRequest request, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<BusLocationDTO>> getLocationHistory(Long busId, LocalDate date, String username) {
        return null;
    }

    @Override
    public ResponseMessage rideWithCard(Long busId, Long cardId, CardType cardType, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<BusRideDTO>> getBusRides(Long busId, String username) {
        return null;
    }

    @Override
    public ResponseMessage assignRoute(Long busId, Long routeId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId, String username) {
        return null;
    }
}
