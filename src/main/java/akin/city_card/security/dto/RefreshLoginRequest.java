package akin.city_card.security.dto;

import akin.city_card.validations.ValidPassword;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshLoginRequest {
    private String refreshToken;
    @ValidPassword
    private String password;
    private String ipAddress;
    private String deviceInfo;

    private String deviceUuid;  // Cihaz benzersiz ID (örn: UUID)
    private String fcmToken;    // Firebase Cloud Messaging token (bildirimler için)
    private String appVersion;  // Uygulama versiyonu (örn: 1.3.2)
    private String platform;    // Platform (örn: Android 14 / iOS 17)

    private Double latitude;    // Enlem
    private Double longitude;   // Boylam
}
