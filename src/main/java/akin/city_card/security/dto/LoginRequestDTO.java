package akin.city_card.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDTO {
    private String telephone; // Kullanıcı numarası
    private String password;   // Kullanıcı şifresi
    private String ipAddress;  // Kullanıcının giriş yaptığı IP adresi
    private String deviceInfo; // Kullanıcının giriş yaptığı cihaz bilgisi
}
