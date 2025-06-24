package akin.city_card.security.dto;

import lombok.Data;

@Data
public class LoginPhoneVerifyCodeRequest {
    private String code;
    private String ipAddress;  // Kullanıcının giriş yaptığı IP adresi
    private String deviceInfo; // Kullanıcının giriş yaptığı cihaz bilgisi
    private String appVersion;
    private String platform;
}
