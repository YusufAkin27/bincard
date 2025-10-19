// BusSearchRequest.java - Arama için
package akin.city_card.bus.core.request;

import akin.city_card.bus.model.BusStatus;
import lombok.Data;

@Data
public class BusSearchRequest {
    private String numberPlate;
    private Long routeId;
    private Long driverId;
    private BusStatus status;
    private Boolean active;
    private Double minFare;
    private Double maxFare;
    private Integer minCapacity;
    private Integer maxCapacity;
}