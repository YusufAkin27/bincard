package akin.city_card.security.dto;

import akin.city_card.validations.ValidVerifyCode;
import lombok.Data;

@Data
public class LoginPhoneVerifyCodeRequest {
    @ValidVerifyCode
    private String code;

    private String deviceInfo;
    private String platform;
    private String appVersion;
    private String deviceUuid;
    private String fcmToken;

    // Konum bilgileri
    private Double latitude;
    private Double longitude;
}
