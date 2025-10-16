package akin.city_card.security.dto;

import akin.city_card.validations.ValidPassword;
import akin.city_card.validations.ValidTelephone;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDTO {

    // 🔐 Kimlik bilgileri
    @ValidTelephone
    private String telephone;   // Kullanıcı numarası (örn: telefon)
    @ValidPassword
    private String password;    // Şifre

    // 🌐 Ağ & cihaz bilgileri
    private String ipAddress;   // IP adresi
    private String deviceInfo;  // Cihaz açıklaması (örn: Xiaomi Redmi Note 11)
    private String deviceUuid;  // Cihaz benzersiz ID (örn: UUID)
    private String appVersion;  // Uygulama versiyonu (örn: 1.3.2)
    private String platform;    // Platform (örn: Android 14 / iOS 17)

    // 📍 Konum bilgileri
    private Double latitude;    // Enlem
    private Double longitude;   // Boylam
}
