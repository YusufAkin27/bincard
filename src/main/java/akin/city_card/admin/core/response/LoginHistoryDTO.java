package akin.city_card.admin.core.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class LoginHistoryDTO {
    private String ipAddress;
    private String device;
    private String platform;
    private String appVersion;
    private LocalDateTime loginAt;
}
