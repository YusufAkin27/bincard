package akin.city_card.bus.core.converter;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusRide;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class BusConverterImpl implements BusConverter {

    @Override
    public BusDTO toBusDTO(Bus bus) {
        if (bus == null) return null;
        BusDTO dto = new BusDTO();
        dto.setId(bus.getId());
        dto.setNumberPlate(bus.getNumberPlate());
        dto.setDriverName(bus.getDriver() != null ? bus.getDriver().getProfileInfo().getName()+bus.getDriver().getProfileInfo().getSurname() : null);
        dto.setRouteName(bus.getRoute() != null ? bus.getRoute().getName() : null);
        dto.setActive(bus.isActive());
        dto.setFare(bus.getFare());
        dto.setCurrentLatitude(bus.getCurrentLatitude());
        dto.setCurrentLongitude(bus.getCurrentLongitude());
        return dto;
    }

    @Override
    public List<BusDTO> toBusDTOList(List<Bus> buses) {
        return buses.stream().map(this::toBusDTO).collect(Collectors.toList());
    }

    @Override
    public Bus fromCreateBusRequest(CreateBusRequest request) {
        Bus bus = new Bus();
        bus.setNumberPlate(request.getNumberPlate());
        bus.setFare(request.getFare());
        bus.setActive(true);
        return bus;
    }

    @Override
    public void updateBusFromRequest(Bus bus, UpdateBusRequest request) {
        bus.setNumberPlate(request.getNumberPlate());
        bus.setFare(request.getFare());
        bus.setActive(request.isActive());
    }

    @Override
    public BusLocationDTO toBusLocationDTO(BusLocation location) {
        if (location == null) return null;
        BusLocationDTO dto = new BusLocationDTO();
        dto.setLatitude(location.getLatitude());
        dto.setLongitude(location.getLongitude());
        dto.setTimestamp(location.getTimestamp());
        return dto;
    }

    @Override
    public List<BusLocationDTO> toBusLocationDTOList(List<BusLocation> locations) {
        return locations.stream().map(this::toBusLocationDTO).collect(Collectors.toList());
    }

    @Override
    public BusLocation fromUpdateLocationRequest(UpdateLocationRequest request) {
        BusLocation location = new BusLocation();
        location.setLatitude(request.getLatitude());
        location.setLongitude(request.getLongitude());
        return location;
    }

    @Override
    public BusRideDTO toBusRideDTO(BusRide ride) {
        if (ride == null) return null;
        BusRideDTO dto = new BusRideDTO();
        dto.setRideId(ride.getId());
        dto.setBusPlate(ride.getBus().getNumberPlate());
        dto.setBoardingTime(ride.getBoardingTime());
        dto.setFareCharged(ride.getFareCharged());
        dto.setStatus(ride.getStatus());
        return dto;
    }

    @Override
    public List<BusRideDTO> toBusRideDTOList(List<BusRide> rides) {
        return rides.stream().map(this::toBusRideDTO).collect(Collectors.toList());
    }
}
