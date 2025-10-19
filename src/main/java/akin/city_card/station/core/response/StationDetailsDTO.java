package akin.city_card.station.core.response;

import akin.city_card.route.core.response.RouteWithNextBusDTO;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class StationDetailsDTO {
    private Long id;
    private String name;
    private double latitude;
    private double longitude;
    private boolean active;
    private String type; // StationType enum değerinin adı
    private List<RouteWithNextBusDTO> routes;
}
