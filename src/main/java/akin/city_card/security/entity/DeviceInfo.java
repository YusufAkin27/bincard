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
    private String ipAddress;
    private String userAgent;
    private String deviceType;       // Mobile, Desktop, Tablet vs.
    private String city;             // GeoIP şehir
    private String region;           // GeoIP bölge
    private String country;          // GeoIP ülke
    private String timezone;         // GeoIP timezone
    private String org;              // GeoIP org bilgisi
}