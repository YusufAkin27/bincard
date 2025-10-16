package akin.city_card.user.core.request;

import akin.city_card.validations.ValidPassword;
import lombok.Data;

@Data
public class PasswordResetRequest {
    private String resetToken;
    @ValidPassword
    private String newPassword;
}
