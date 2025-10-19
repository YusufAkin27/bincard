package akin.city_card.user.core.request;

import akin.city_card.validations.ValidTelephone;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResendPhoneVerificationRequest {


    @ValidTelephone
    private String telephone;

    private String ipAddress;     // Client IP
    private String userAgent;     // Cihaz bilgisi (Android, iOS vs.)
    private String deviceUuid;    // Cihazın UUID'si (mobil cihazdan alınacak)
}
