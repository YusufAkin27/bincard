package akin.city_card.location.core.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class LocationDTO {
    private Double latitude;
    private Double longitude;
    private LocalDateTime recordedAt;
    private Long userId;
}
