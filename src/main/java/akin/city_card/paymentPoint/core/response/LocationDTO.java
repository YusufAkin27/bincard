package akin.city_card.paymentPoint.core.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LocationDTO {
    private Double latitude;
    private Double longitude;
}
