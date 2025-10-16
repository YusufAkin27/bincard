package akin.city_card.station.core.response;

import akin.city_card.station.model.Station;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RoutePosition {
    private int sequenceOrder;
    private Station station;
}