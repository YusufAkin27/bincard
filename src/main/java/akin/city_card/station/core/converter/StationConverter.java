package akin.city_card.station.core.converter;

import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.route.core.response.RouteWithNextBusDTO;
import akin.city_card.station.core.response.StationDetailsDTO;
import akin.city_card.station.model.Station;

import java.util.List;

public interface StationConverter {
    StationDTO toDTO(Station station);

    StationDetailsDTO toStationDetailsDto(Station station, List<RouteWithNextBusDTO> routes);

}
