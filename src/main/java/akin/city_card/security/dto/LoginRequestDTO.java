package akin.city_card.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDTO {

    // 🔐 Kimlik bilgileri
    private String telephone;   // Kullanıcı numarası (örn: telefon)
    private String password;    // Şifre

    // 🌐 Ağ & cihaz bilgileri
    private String ipAddress;   // IP adresi
    private String deviceInfo;  // Cihaz açıklaması (örn: Xiaomi Redmi Note 11)
    private String deviceUuid;  // Cihaz benzersiz ID (örn: UUID)
    private String fcmToken;    // Firebase Cloud Messaging token (bildirimler için)
    private String appVersion;  // Uygulama versiyonu (örn: 1.3.2)
    private String platform;    // Platform (örn: Android 14 / iOS 17)

    // 📍 Konum bilgileri
    private Double latitude;    // Enlem
    private Double longitude;   // Boylam
}
