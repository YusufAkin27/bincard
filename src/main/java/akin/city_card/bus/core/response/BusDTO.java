package akin.city_card.bus.core.response;

import akin.city_card.bus.model.BusStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BusDTO {
    private Long id;
    private String numberPlate;
    private String driverName;
    private boolean isActive;
    private BusStatus status;
    private String statusDisplayName;
    private int capacity;
    private int currentPassengerCount;
    private Double occupancyRate;
    private double baseFare;

    // Rota bilgileri
    private String assignedRouteName;
    private String assignedRouteCode;
    private String currentDirectionName;

    // Durak bilgileri
    private StationDTO lastSeenStation;
    private LocalDateTime lastSeenStationTime;
    private StationDTO nextStation;
    private Integer estimatedArrivalMinutes;

    // Konum bilgileri
    private Double currentLatitude;
    private Double currentLongitude;
    private LocalDateTime lastLocationUpdate;
    private Double lastKnownSpeed;

    // Audit bilgileri
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdByUsername;
    private String updatedByUsername;

    // Hesaplanan alanlar
    private boolean canTakePassengers;
    private boolean isFull;
    private boolean isOperational;
}