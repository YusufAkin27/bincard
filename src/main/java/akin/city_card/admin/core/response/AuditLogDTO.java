package akin.city_card.admin.core.response;

import akin.city_card.admin.model.ActionType;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class AuditLogDTO {

    private Long id;

    @Enumerated(EnumType.STRING)
    private ActionType action;

    private String description;

    private LocalDateTime timestamp;

    private String ipAddress;
    private String deviceInfo;
}
