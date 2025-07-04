package akin.city_card.bus.core.response;

import akin.city_card.bus.model.RideStatus;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
public class BusRideDTO {
    private Long rideId;
    private String busPlate;
    private LocalDateTime boardingTime;
    private BigDecimal fareCharged;
    private RideStatus status;
}
