package akin.city_card.station.core.converter;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.route.core.response.RouteWithNextBusDTO;
import akin.city_card.station.core.response.StationDetailsDTO;
import akin.city_card.station.model.Station;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class StationConverterImpl implements StationConverter {

    @Override
    public StationDTO toDTO(Station station) {
        return StationDTO.builder()
                .id(station.getId())
                .name(station.getName())
                .latitude(station.getLocation().getLatitude())
                .longitude(station.getLocation().getLongitude())
                .type(station.getType().name())
                .active(station.isActive())
                .city(station.getAddress().getCity())
                .district(station.getAddress().getDistrict())
                .street(station.getAddress().getStreet())
                .postalCode(station.getAddress().getPostalCode())
                .build();
    }

    @Override
    public StationDetailsDTO toStationDetailsDto(Station station, List<RouteWithNextBusDTO> routes) {
        StationDetailsDTO dto = new StationDetailsDTO();
        dto.setId(station.getId());
        dto.setName(station.getName());
        dto.setLatitude(station.getLocation().getLatitude());
        dto.setLongitude(station.getLocation().getLongitude());
        dto.setType(station.getType().name());
        dto.setActive(station.isActive());
        dto.setRoutes(routes);
        return dto;
    }


}
