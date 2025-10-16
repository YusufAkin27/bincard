package akin.city_card.bus.core.response;

import akin.city_card.bus.model.RideStatus;
import akin.city_card.buscard.model.CardType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BusRideDTO {
    private Long rideId;
    private String busPlate;
    private Long cardId;
    private CardType cardType;
    private LocalDateTime boardingTime;
    private BigDecimal fareCharged;
    private RideStatus status;
}