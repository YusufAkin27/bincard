package akin.city_card.bus.core.response;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BusLocationDTO {
    private double latitude;
    private double longitude;
    private LocalDateTime timestamp;
}
