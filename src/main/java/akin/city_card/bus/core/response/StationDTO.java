package akin.city_card.bus.core.response;

import lombok.Data;

@Data
public class StationDTO {
    private Long id;
    private String name;
    private double latitude;
    private double longitude;
}
