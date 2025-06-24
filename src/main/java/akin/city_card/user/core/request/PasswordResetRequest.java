package akin.city_card.user.core.request;

import lombok.Data;

@Data
public class PasswordResetRequest {
    private String resetToken;
    private String newPassword;
}
