package akin.city_card.user.core.request;


import lombok.Data;


@Data
public class GeoAlertRequest {


    private Long routeId;

    private Long stationId;

    private double radiusMeters;

    private int notifyBeforeMinutes;

    private String alertName;

}
