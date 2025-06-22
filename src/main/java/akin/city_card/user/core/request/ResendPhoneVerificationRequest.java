package akin.city_card.user.core.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResendPhoneVerificationRequest {


    private String telephone;

    private String ipAddress;     // Client IP
    private String userAgent;     // Cihaz bilgisi (Android, iOS vs.)
    private String deviceUuid;    // Cihazın UUID'si (mobil cihazdan alınacak)
}
