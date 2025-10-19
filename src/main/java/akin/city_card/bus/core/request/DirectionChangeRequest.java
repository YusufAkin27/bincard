package akin.city_card.bus.core.request;

import lombok.Data;

@Data
public class DirectionChangeRequest {
    private Long newDirectionId;
    private String reason; // Opsiyonel - değişim sebebi
}