package akin.city_card.user.core.request;

import akin.city_card.validations.ValidPassword;
import lombok.Data;

@Data
public class ChangePasswordRequest {
    @ValidPassword
    private String currentPassword;
    @ValidPassword
    private String newPassword;
}
