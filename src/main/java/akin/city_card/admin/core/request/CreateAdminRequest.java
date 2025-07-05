package akin.city_card.admin.core.request;

import akin.city_card.validations.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateAdminRequest {
    private String name;
    private String surname;
    @ValidTelephone
    @UniquePhoneNumber
    private String telephone;
    @ValidPassword
    private String password;
    @ValidEmail
    @UniqueEmail
    private String email;
    private String ipAddress;
    private String deviceUuid;
    private String fcmToken;


    private String userAgent;
}
