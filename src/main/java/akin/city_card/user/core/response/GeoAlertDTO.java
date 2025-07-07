package akin.city_card.user.core.response;

import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class GeoAlertDTO {

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private Long id;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private Long userId;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private Long routeId;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private Long stationId;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private double radiusMeters;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private int notifyBeforeMinutes;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private String alertName;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private LocalDateTime createdAt;

    @JsonView({Views.Public.class, Views.User.class, Views.Admin.class, Views.SuperAdmin.class})
    private LocalDateTime updatedAt;
}
