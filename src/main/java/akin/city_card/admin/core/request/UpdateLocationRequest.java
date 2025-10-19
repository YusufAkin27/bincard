package akin.city_card.admin.core.request;

import akin.city_card.validations.ValidLatitude;
import akin.city_card.validations.ValidLongitude;
import lombok.Data;

@Data
public class UpdateLocationRequest {
    @ValidLatitude
    private Double latitude;
    @ValidLongitude
    private Double longitude;

    private Double speed;
    private Double accuracy;
}
