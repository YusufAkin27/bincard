package akin.city_card.bus.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DriverHistoryDTO {
    private Long driverId;
    private String driverName;
    private LocalDateTime assignedDate;
    private LocalDateTime unassignedDate;
    private String reason;
}
