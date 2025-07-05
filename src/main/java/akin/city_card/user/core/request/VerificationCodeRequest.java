package akin.city_card.user.core.request;

import akin.city_card.validations.ValidVerifyCode;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationCodeRequest {
    @NotBlank(message = "Doğrulama kodu boş olamaz")
    @ValidVerifyCode
    private String code;

}
