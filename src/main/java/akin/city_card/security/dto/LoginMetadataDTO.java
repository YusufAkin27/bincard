package akin.city_card.security.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginMetadataDTO {
    private String ipAddress;
    private String deviceInfo;
    private String deviceUuid;
    private String fcmToken;
    private String platform;
    private String appVersion;
    private Double latitude;
    private Double longitude;
}
