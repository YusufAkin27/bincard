package akin.city_card.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshLoginRequest {
    private String refreshToken;
    private String password;
    private String ipAddress;
    private String deviceInfo;
}
