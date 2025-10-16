package akin.city_card.bus.core.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class StationDTO {
    private Long id;
    private String name;
    private double latitude;
    private double longitude;
    private boolean active;
    private String type; // StationType enum değerinin adı
    private String city;
    private String district;
    private String street;
    private String postalCode;
}
