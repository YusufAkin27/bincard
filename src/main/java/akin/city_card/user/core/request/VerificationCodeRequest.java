package akin.city_card.user.core.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationCodeRequest {
    private String code;
    private String ipAddress;
    private String userAgent;
}
