package akin.city_card.geoAlert.core.response;

import akin.city_card.geoAlert.model.GeoAlertStatus;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class GeoAlertDTO {

    @JsonView(Views.User.class)
    private Long id;

    @JsonView(Views.User.class)
    private String alertName;

    @JsonView(Views.User.class)
    private String routeName;

    @JsonView(Views.User.class)
    private String routeCode;

    @JsonView(Views.User.class)
    private String stationName;

    @JsonView(Views.User.class)
    private int notifyBeforeMinutes;

    @JsonView(Views.User.class)
    private double radiusMeters;

    @JsonView(Views.User.class)
    private GeoAlertStatus status;

    @JsonView(Views.User.class)
    private String statusDisplayName;

    @JsonView(Views.User.class)
    private LocalDateTime createdAt;

    @JsonView(Views.User.class)
    private LocalDateTime notifiedAt;

    @JsonView(Views.User.class)
    private LocalDateTime cancelledAt;

    @JsonView(Views.User.class)
    private String notes;

    @JsonView(Views.User.class)
    private String triggeredByBusPlate;

    @JsonView(Views.User.class)
    private Integer actualNotificationMinutes;

    // Computed fields
    @JsonView(Views.User.class)
    private boolean isExpired;

    @JsonView(Views.User.class)
    private String timeUntilExpiry;

    public String getStatusDisplayName() {
        return status != null ? status.getDisplayName() : null;
    }
}