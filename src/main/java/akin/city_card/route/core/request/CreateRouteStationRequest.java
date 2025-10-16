package akin.city_card.route.core.request;

import lombok.Data;

@Data
public class CreateRouteStationRequest {
    private Long fromStationId;
    private Long toStationId;
    private Integer estimatedTravelTimeMinutes;
    private Double distanceKm;
    private String notes;
}