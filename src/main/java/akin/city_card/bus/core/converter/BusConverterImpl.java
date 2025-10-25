package akin.city_card.bus.core.converter;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusRide;
import akin.city_card.news.core.response.PageDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class BusConverterImpl implements BusConverter {

    @Override
    public BusDTO toBusDTO(Bus bus) {
        if (bus == null) return null;

        return BusDTO.builder()
                .id(bus.getId())
                .numberPlate(bus.getNumberPlate())
                .driverName(bus.getDriverDisplayName())
                .isActive(bus.isActive())
                .status(bus.getStatus())
                .statusDisplayName(bus.getStatus() != null ? bus.getStatus().getDisplayName() : null)
                .assignedRouteName(bus.getRouteDisplayName())
                .assignedRouteCode(bus.getRouteCode())
                .currentDirectionName(bus.getCurrentDirectionName())
                .lastSeenStation(convertStationToDTO(bus.getLastSeenStation()))
                .lastSeenStationTime(bus.getLastSeenStationTime())
                .nextStation(convertStationToDTO(bus.getNextStation()))
                .estimatedArrivalMinutes(bus.getEstimatedArrivalMinutes())
                .currentLatitude(bus.getCurrentLatitude())
                .currentLongitude(bus.getCurrentLongitude())
                .lastLocationUpdate(bus.getLastLocationUpdate())
                .lastKnownSpeed(bus.getLastKnownSpeed())
                .createdAt(bus.getCreatedAt())
                .updatedAt(bus.getUpdatedAt())
                .createdByUsername(bus.getCreatedBy() != null ? bus.getCreatedBy().getUsername() : null)
                .updatedByUsername(bus.getUpdatedBy() != null ? bus.getUpdatedBy().getUsername() : null)
                .canTakePassengers(bus.getStatus() != null ? bus.getStatus().canTakePassengers() : false)
                .isOperational(bus.getStatus() != null ? bus.getStatus().isOperational() : false)
                .build();
    }

    @Override
    public List<BusDTO> toBusDTOList(List<Bus> buses) {
        return buses.stream()
                .map(this::toBusDTO)
                .collect(Collectors.toList());
    }

    @Override
    public Bus fromCreateBusRequest(CreateBusRequest request) {
        Bus bus = new Bus();
        bus.setNumberPlate(request.getNumberPlate().trim().toUpperCase());
        bus.setActive(true);
        return bus;
    }

    @Override
    public void updateBusFromRequest(Bus bus, UpdateBusRequest request) {
        if (request.getNumberPlate() != null && !request.getNumberPlate().trim().isEmpty()) {
            bus.setNumberPlate(request.getNumberPlate().trim().toUpperCase());
        }

        if (request.getActive() != null) {
            bus.setActive(request.getActive());
        }

        if (request.getStatus() != null) {
            bus.setStatus(request.getStatus());
        }
    }

    @Override
    public BusLocationDTO toBusLocationDTO(BusLocation location) {
        if (location == null) return null;

        BusLocationDTO dto = new BusLocationDTO();
        dto.setLatitude(location.getLatitude());
        dto.setLongitude(location.getLongitude());
        dto.setTimestamp(location.getTimestamp());
        dto.setSpeed(location.getSpeed());
        dto.setAccuracy(location.getAccuracy());

        if (location.getClosestStation() != null) {
            dto.setClosestStationName(location.getClosestStation().getName());
            dto.setDistanceToClosestStation(location.getDistanceToClosestStation());
        }

        return dto;
    }

    @Override
    public List<BusLocationDTO> toBusLocationDTOList(List<BusLocation> locations) {
        return locations.stream()
                .map(this::toBusLocationDTO)
                .collect(Collectors.toList());
    }

    @Override
    public BusLocation fromUpdateLocationRequest(UpdateLocationRequest request) {
        BusLocation location = new BusLocation();
        location.setLatitude(request.getLatitude());
        location.setLongitude(request.getLongitude());

        if (request.getSpeed() != null) {
            location.setSpeed(request.getSpeed());
        }
        if (request.getAccuracy() != null) {
            location.setAccuracy(request.getAccuracy());
        }

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

        if (ride.getBusCard() != null) {
            dto.setCardId(ride.getBusCard().getId());
            dto.setCardType(ride.getBusCard().getType());
        }

        return dto;
    }

    @Override
    public List<BusRideDTO> toBusRideDTOList(List<BusRide> rides) {
        return rides.stream()
                .map(this::toBusRideDTO)
                .collect(Collectors.toList());
    }

    @Override
    public PageDTO<BusDTO> toPageDTO(Page<Bus> busPage) {
        List<BusDTO> content = busPage.getContent().stream()
                .map(this::toBusDTO)
                .collect(Collectors.toList());

        PageDTO<BusDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(content);
        pageDTO.setPageNumber(busPage.getNumber());
        pageDTO.setPageSize(busPage.getSize());
        pageDTO.setTotalElements(busPage.getTotalElements());
        pageDTO.setTotalPages(busPage.getTotalPages());

        return pageDTO;
    }

    public PageDTO<BusLocationDTO> toLocationPageDTO(Page<BusLocation> page) {
        List<BusLocationDTO> dtoList = page.getContent().stream()
                .map(this::toBusLocationDTO)
                .toList();

        PageDTO pageDTO = new PageDTO<>();
        pageDTO.setContent(dtoList);
        pageDTO.setPageNumber(page.getNumber());
        pageDTO.setPageSize(page.getSize());
        pageDTO.setTotalElements(page.getTotalElements());
        pageDTO.setTotalPages(page.getTotalPages());
        return pageDTO;
    }


    // Helper method - Station'ı StationDTO'ya çevir
    private StationDTO convertStationToDTO(akin.city_card.station.model.Station station) {
        if (station == null) return null;

        return StationDTO.builder()
                .id(station.getId())
                .name(station.getName())
                .latitude(station.getLocation() != null ? station.getLocation().getLatitude() : 0.0)
                .longitude(station.getLocation() != null ? station.getLocation().getLongitude() : 0.0)
                .active(station.isActive())
                .type(station.getType() != null ? station.getType().name() : null)
                .city(station.getAddress() != null ? station.getAddress().getCity() : null)
                .district(station.getAddress() != null ? station.getAddress().getDistrict() : null)
                .street(station.getAddress() != null ? station.getAddress().getStreet() : null)
                .postalCode(station.getAddress() != null ? station.getAddress().getPostalCode() : null)
                .build();
    }
}