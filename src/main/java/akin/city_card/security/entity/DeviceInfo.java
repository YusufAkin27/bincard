package akin.city_card.security.entity;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceInfo {
    private String fcmToken;
    private String deviceUuid;
    private String ipAddress;
}
