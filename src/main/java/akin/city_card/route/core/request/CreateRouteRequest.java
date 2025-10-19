package akin.city_card.route.core.request;

import akin.city_card.route.model.RouteType;
import akin.city_card.route.model.TimeSlot;
import lombok.Data;

import java.util.List;


@Data
public class CreateRouteRequest {
    private String routeName;
    private String routeCode;
    private String description;
    private RouteType routeType;
    private String color;
    private Long startStationId;
    private Long endStationId;
    private Integer estimatedDurationMinutes;
    private Double totalDistanceKm;

    // Schedule
    private List<TimeSlot> weekdayHours;
    private List<TimeSlot> weekendHours;

    // Gidiş yönü durakları (sıralı)
    private List<CreateRouteStationRequest> outgoingStations;

    // Dönüş yönü durakları (sıralı) - opsiyonel, verilmezse otomatik ters sıra
    private List<CreateRouteStationRequest> returnStations;
}