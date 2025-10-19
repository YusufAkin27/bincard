package akin.city_card.station.core.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SearchStationRequest {
    private double latitude;
    private double longitude;
    private String query;
}
