package akin.city_card.bus.core.response;

import lombok.Data;

@Data
public class BusDTO {
    private Long id;
    private String numberPlate;
    private String routeName;
    private String driverName;
    private boolean active;
    private double fare;
    private double currentLatitude;
    private double currentLongitude;
}
