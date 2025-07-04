package akin.city_card.bus.core.request;

import lombok.Data;

@Data
public class UpdateLocationRequest {
    private double latitude;
    private double longitude;
}
