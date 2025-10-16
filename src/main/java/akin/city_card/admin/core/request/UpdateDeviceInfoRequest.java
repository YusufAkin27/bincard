package akin.city_card.admin.core.request;

import lombok.Data;

@Data
public class UpdateDeviceInfoRequest {

    private String fcmToken;

    private String ipAddress;              // Güncel IP adresi

    private Double lastKnownLatitude;      // Lokasyon
    private Double lastKnownLongitude;

    private String lastLoginDevice;        // Örn: "Xiaomi Redmi Note 11"
    private String lastLoginPlatform;      // Örn: "Android 14" / "iOS 17.4"
    private String lastLoginAppVersion;    // Örn: "1.2.4"

    private String profilePicture;         // İsteğe bağlı profil fotoğrafı güncellemesi

}