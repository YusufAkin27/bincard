package akin.city_card.admin.core.response;

import akin.city_card.admin.model.ActionType;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class AuditLogDTO {
    @JsonView(Views.SuperAdmin.class)
    private Long id;

    @JsonView({Views.Public.class, Views.SuperAdmin.class})
    @Enumerated(EnumType.STRING)
    private ActionType action;

    @JsonView(Views.SuperAdmin.class)
    private String description;

    @JsonView(Views.SuperAdmin.class)
    private LocalDateTime timestamp;

    @JsonView(Views.SuperAdmin.class)
    private String ipAddress;

    @JsonView(Views.SuperAdmin.class)
    private String deviceInfo;


}
