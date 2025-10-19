package akin.city_card.security.dto;

import lombok.Data;

@Data
public class UpdateAccessTokenRequestDTO {
    private String refreshToken; // Yenileme tokenı
    private String ipAddress;    // Kullanıcının talep sırasında kullandığı IP adresi
    private String deviceInfo;   // Kullanıcının talep sırasında kullandığı cihaz bilgisi

    private String deviceUuid;  // Cihaz benzersiz ID (örn: UUID)
    private String fcmToken;    // Firebase Cloud Messaging token (bildirimler için)
    private String appVersion;  // Uygulama versiyonu (örn: 1.3.2)
    private String platform;    // Platform (örn: Android 14 / iOS 17)

    // 📍 Konum bilgileri
    private Double latitude;    // Enlem
    private Double longitude;   // Boylam
}
