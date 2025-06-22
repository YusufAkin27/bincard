package akin.city_card.user.core.request;

import lombok.Data;

@Data
public class PasswordResetRequest {
    private String emailOrPhone;
    private String code;
    private String newPassword;
}
